using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.crypto.test
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using X509ObjectIdentifiers = org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using SHA224Digest = org.bouncycastle.crypto.digests.SHA224Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA3Digest = org.bouncycastle.crypto.digests.SHA3Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHA512tDigest = org.bouncycastle.crypto.digests.SHA512tDigest;
	using RSAKeyParameters = org.bouncycastle.crypto.@params.RSAKeyParameters;
	using RSAPrivateCrtKeyParameters = org.bouncycastle.crypto.@params.RSAPrivateCrtKeyParameters;
	using RSADigestSigner = org.bouncycastle.crypto.signers.RSADigestSigner;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class RSADigestSignerTest : SimpleTest
	{
		public override string getName()
		{
			return "RSADigestSigner";
		}

		public override void performTest()
		{
			BigInteger rsaPubMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
			BigInteger rsaPubExp = new BigInteger(Base64.decode("EQ=="));
			BigInteger rsaPrivMod = new BigInteger(Base64.decode("AIASoe2PQb1IP7bTyC9usjHP7FvnUMVpKW49iuFtrw/dMpYlsMMoIU2jupfifDpdFxIktSB4P+6Ymg5WjvHKTIrvQ7SR4zV4jaPTu56Ys0pZ9EDA6gb3HLjtU+8Bb1mfWM+yjKxcPDuFjwEtjGlPHg1Vq+CA9HNcMSKNn2+tW6qt"));
			BigInteger rsaPrivDP = new BigInteger(Base64.decode("JXzfzG5v+HtLJIZqYMUefJfFLu8DPuJGaLD6lI3cZ0babWZ/oPGoJa5iHpX4Ul/7l3s1PFsuy1GhzCdOdlfRcQ=="));
			BigInteger rsaPrivDQ = new BigInteger(Base64.decode("YNdJhw3cn0gBoVmMIFRZzflPDNthBiWy/dUMSRfJCxoZjSnr1gysZHK01HteV1YYNGcwPdr3j4FbOfri5c6DUQ=="));
			BigInteger rsaPrivExp = new BigInteger(Base64.decode("DxFAOhDajr00rBjqX+7nyZ/9sHWRCCp9WEN5wCsFiWVRPtdB+NeLcou7mWXwf1Y+8xNgmmh//fPV45G2dsyBeZbXeJwB7bzx9NMEAfedchyOwjR8PYdjK3NpTLKtZlEJ6Jkh4QihrXpZMO4fKZWUm9bid3+lmiq43FwW+Hof8/E="));
			BigInteger rsaPrivP = new BigInteger(Base64.decode("AJ9StyTVW+AL/1s7RBtFwZGFBgd3zctBqzzwKPda6LbtIFDznmwDCqAlIQH9X14X7UPLokCDhuAa76OnDXb1OiE="));
			BigInteger rsaPrivQ = new BigInteger(Base64.decode("AM3JfD79dNJ5A3beScSzPtWxx/tSLi0QHFtkuhtSizeXdkv5FSba7lVzwEOGKHmW829bRoNxThDy4ds1IihW1w0="));
			BigInteger rsaPrivQinv = new BigInteger(Base64.decode("Lt0g7wrsNsQxuDdB8q/rH8fSFeBXMGLtCIqfOec1j7FEIuYA/ACiRDgXkHa0WgN7nLXSjHoy630wC5Toq8vvUg=="));
			RSAKeyParameters rsaPublic = new RSAKeyParameters(false, rsaPubMod, rsaPubExp);
			RSAPrivateCrtKeyParameters rsaPrivate = new RSAPrivateCrtKeyParameters(rsaPrivMod, rsaPubExp, rsaPrivExp, rsaPrivP, rsaPrivQ, rsaPrivDP, rsaPrivDQ, rsaPrivQinv);

			checkDigest(rsaPublic, rsaPrivate, new SHA1Digest(), X509ObjectIdentifiers_Fields.id_SHA1);

			checkDigest(rsaPublic, rsaPrivate, new SHA224Digest(), NISTObjectIdentifiers_Fields.id_sha224);
			checkDigest(rsaPublic, rsaPrivate, new SHA256Digest(), NISTObjectIdentifiers_Fields.id_sha256);
			checkDigest(rsaPublic, rsaPrivate, new SHA384Digest(), NISTObjectIdentifiers_Fields.id_sha384);
			checkDigest(rsaPublic, rsaPrivate, new SHA512Digest(), NISTObjectIdentifiers_Fields.id_sha512);
			checkDigest(rsaPublic, rsaPrivate, new SHA512tDigest(224), NISTObjectIdentifiers_Fields.id_sha512_224);
			checkDigest(rsaPublic, rsaPrivate, new SHA512tDigest(256), NISTObjectIdentifiers_Fields.id_sha512_256);

			checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(224), NISTObjectIdentifiers_Fields.id_sha3_224);
			checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(256), NISTObjectIdentifiers_Fields.id_sha3_256);
			checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(384), NISTObjectIdentifiers_Fields.id_sha3_384);
			checkDigest(rsaPublic, rsaPrivate, new SHA3Digest(512), NISTObjectIdentifiers_Fields.id_sha3_512);
		}

		private void checkDigest(RSAKeyParameters rsaPublic, RSAPrivateCrtKeyParameters rsaPrivate, Digest digest, ASN1ObjectIdentifier digOid)
		{
			byte[] msg = new byte[] {1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23};

			RSADigestSigner signer = new RSADigestSigner(digest);
			signer.init(true, rsaPrivate);
			signer.update(msg, 0, msg.Length);
			byte[] sig = signer.generateSignature();

			signer = new RSADigestSigner(digest, digOid);
			signer.init(false, rsaPublic);
			signer.update(msg, 0, msg.Length);
			if (!signer.verifySignature(sig))
			{
				fail("RSA Digest Signer failed.");
			}
		}

		public static void Main(string[] args)
		{
			runTest(new RSADigestSignerTest());
		}
	}

}