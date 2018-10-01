function MasterKey(seed) {
    var ecparams = EllipticCurve.getSECCurveByName("secp256k1");
    // MinSeedBytes is the minimum number of bytes allowed for a seed to
    // a master node.
    const MinSeedBytes = 16 // 128 bits

    // MaxSeedBytes is the maximum number of bytes allowed for a seed to
    // a master node.
    const MaxSeedBytes = 64 // 512 bits

    // masterKey is the master key used along with a random seed used to generate
    // the master node in the hierarchical tree.
    const masterKey = "Bitcoin seed"

    // HardenedKeyStart is the index at which a hardended key starts.  Each
    // extended key has 2^31 normal child keys and 2^31 hardned child keys.
    // Thus the range for normal child keys is [0, 2^31 - 1] and the range
    // for hardened child keys is [2^31, 2^32 - 1].
    //const HardenedKeyStart = 0x80000000 // 2^31
    const HardenedKeyStart = 0x80000000;
    //const HardenedKeyStart = forge.util.createBuffer('80000000', 'hex');

    // BIP32 hierarchical deterministic extended key magics
    // HDPrivateKeyID [4]byte
    const HDPrivateKeyID = forge.util.createBuffer('0000', 'hex');


    // TODO:  validate size of seed and format is hex
    // Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
    // if len(seed) < MinSeedBytes || len(seed) > MaxSeedBytes {
    // 	return nil, ErrInvalidSeedLen
    // }

    var bytes = forge.util.hexToBytes(seed);

    // First take the HMAC-SHA512 of the master key and the seed data:
    //   I = HMAC-SHA512(Key = "Bitcoin seed", Data = S)
    var hmac = forge.hmac.create();
    hmac.start('sha512', masterKey);
    hmac.update(bytes);

    var hm=hmac.digest();

    // Split "I" into two 32-byte sequences Il and Ir where:
    //   Il = master secret key
    //   Ir = master chain code
    var secretKey = hm.getBytes(hm.length()/2);
    var chainCode = hm.bytes();

    // ensure the key is usable
    var secretKeyNum = new BigInteger(forge.util.bytesToHex(secretKey),16);

    if (secretKeyNum.compareTo(ecparams.getN()) >= 0 ||
        secretKeyNum.signum() == 0) {
            console.log("bad key");
            NewMaster = false;
    }else{
        //return this.newExtendedKey(HDPrivateKeyID, secretKey, chainCode, forge.util.createBuffer('0000', 'hex'), 0, 0, true)
        this.key = secretKey;
        this.chainCode = chainCode;
        this.depth = 0;
        this.parentFP = forge.util.createBuffer('0000', 'hex');
        this.childNum = 0;
        this.version = HDPrivateKeyID;
        this.isPrivate = true;
    }

    this.Child = function(i) {
        // There are four scenarios that could happen here:
        // 1) Private extended key -> Hardened child private extended key
        // 2) Private extended key -> Non-hardened child private extended key
        // 3) Public extended key -> Non-hardened child public extended key
        // 4) Public extended key -> Hardened child public extended key (INVALID!)

        // Case #4 is invalid, so error out early.
        // A hardened child extended key may not be created from a public
        // extended key.

        var isChildHardened = (i >= HardenedKeyStart);
        if (!this.isPrivate && isChildHardened) {
            return false
        }
        // The data used to derive the child key depends on whether or not the
        // child is hardened per [BIP32].
        //
        // For hardened children:
        //   0x00 || ser256(parentKey) || ser32(i)
        //
        // For normal children:
        //   serP(parentPubKey) || ser32(i)
        const keyLen = 33

        var data = this.makeFilledArray(keyLen+4, '\0');
        if (isChildHardened) {
            // Case #1.
            // When the child is a hardened child, the key is known to be a
            // private key due to the above early return.  Pad it with a
            // leading zero as required by [BIP32] for deriving the child.
            var thisKey = forge.util.createBuffer(this.key,'raw');
            data = this.forgeBufferCopyTo(data, thisKey, 1)
        } else {
            // Case #2 or #3.
            // This is either a public or private extended key, but in
            // either case, the data which is used to derive the child key
            // starts with the secp256k1 compressed public key bytes.
            var thisKey = forge.util.createBuffer(this.pubKeyBytes(),'raw');
            data = this.forgeBufferCopyTo(data, thisKey , 0)
        }

        var post = forge.util.createBuffer(forge.util.hexToBytes(this.decimalToHex(i,4)),'raw');
        data = this.forgeBufferCopyTo(data, post , keyLen)

        // Take the HMAC-SHA512 of the current key's chain code and the derived
        // data:
        //   I = HMAC-SHA512(Key = chainCode, Data = data)
        var hmac = forge.hmac.create();
        hmac.start('sha512', this.chainCode);
        hmac.update(data.bytes());
        var hm=hmac.digest();

        // Split "I" into two 32-byte sequences Il and Ir where:
        //   Il = intermediate key used to derive the child
        //   Ir = child chain code
        var il = hm.getBytes(hm.length()/2);
        var childChainCode = hm.bytes();

        // Both derived public or private keys rely on treating the left 32-byte
        // sequence calculated above (Il) as a 256-bit integer that must be
        // within the valid range for a secp256k1 private key.  There is a small
        // chance (< 1 in 2^127) this condition will not hold, and in that case,
        // a child extended key can't be created for this index and the caller
        // should simply increment to the next index.
        var ilNum = new BigInteger(forge.util.bytesToHex(il),16);
        if (ilNum.compareTo(ecparams.getN()) >= 0 ||
                ilNum.signum() == 0) {
                console.log("bad child");
                return false;
        }
        // The algorithm used to derive the child key depends on whether or not
        // a private or public child is being derived.
        //
        // For private children:
        //   childKey = parse256(Il) + parentKey
        //
        // For public children:
        //   childKey = serP(point(parse256(Il)) + parentKey)

        if (this.isPrivate) {
            // Case #1 or #2.
            // Add the parent private key to the intermediate private key to
            // derive the final child key.
            //
            // childKey = parse256(Il) + parenKey
            var keyNum = new BigInteger(forge.util.bytesToHex(this.key),16)
            ilNum=ilNum.add(keyNum);
            ilNum=ilNum.mod(ecparams.getN())
            var childKey = ilNum.toByteArray();
            isPrivate = true;

        } else {
            // Case #3.
            // Calculate the corresponding intermediate public key for
            // intermediate private key.
            ilpoint = ecparams.getG().multiply(il);
            if (ilpoint.getX().toBigInteger().signum() == 0 ||
                ilpoint.getY().toBigInteger().signum() == 0) {
                    console.log("bad child");
                    return false;
            }

            // Convert the serialized compressed parent public key into X
            // and Y coordinates so it can be added to the intermediate
            // public key.
            var ecPoint = ecparams.getCurve().decodePointHex(this.secretKey);
            // Add the intermediate public key to the parent public key to
            // derive the final child key.
            //
            // childKey = serP(point(parse256(Il)) + parentKey)


        }
        // The fingerprint of the parent for the derived child is the first 4
	    // bytes of the RIPEMD160(BLAKE256(parentPubKey)).

        var pubkey = this.bytesToHex(this.pubKeyBytes());
        var parentFP = this.sha256ripe160(pubkey).substring(0,8);

        return this.newExtendedKey(this.version, childKey, childChainCode, parentFP, this.depth+1, i, isPrivate)
    }

    this.pubKeyBytes = function () {
        if (!this.isPrivate) {
            return this.key;
        }

        // This is a private extended key, so calculate and memoize the public
        // key if needed.
        if (typeof this.pubKey == "undefined") {
            var secretKeyNum = new BigInteger(forge.util.bytesToHex(this.key),16);
            this.pubPoint = ecparams.getG().multiply(secretKeyNum);
            this.pubKey = this.pubPoint.getEncoded(true);
        }
        return this.pubKey;
    }

    // Utility Functions
    this.makeFilledArray = function (len, val) {
        var buffer = forge.util.createBuffer();
        var i = 0;
        while (i < len) {
            buffer.putBytes(val);
            i++;
        }
        return buffer;
    }

    // key values from ecc package are not compatible with forge for some reason.
    // until we sort it out use an alternate function.
    this.bytesToHex = function(bytes) {
        for (var hex = [], i = 0; i < bytes.length; i++) {
            hex.push((bytes[i] >>> 4).toString(16));
            hex.push((bytes[i] & 0xF).toString(16));
        }
        return hex.join("");
    }

    this.forgeBufferCopyTo = function (base,insert,start) {
        var buffer = forge.util.createBuffer();
        var j=insert.length();
        var i=0;
        while(base.length()) {
            var val = base.getBytes(1);
            if (i >= start && j>0) {
                j--;
                buffer.putBytes(insert.getBytes(1));
            }else{
                buffer.putBytes(val);
            }
            i++;
        }
        return buffer;
    }

    this.decimalToHex = function(d, padding) {
        var hex = Number(d).toString(16);
        padding = typeof (padding) === "undefined" || padding === null ? padding = 2 : padding;

        while (hex.length < padding) {
            hex = "0" + hex;
        }
        return hex;
    }

    this.sha256ripe160 =  function (data) {
        var b = CryptoJS.BLAKE256(data);
        return Crypto.RIPEMD160(b.toString(), { asBytes: false });
    }

    this.newExtendedKey = function (version, key, chainCode, parentFP, depth, childNum, isPrivate) {
        var ret = {
            key: key,
            chainCode: chainCode,
            depth: depth,
            parentFP: parentFP,
            childNum: childNum,
            version: version,
            isPrivate: isPrivate
        }
        return ret;
    }

}
