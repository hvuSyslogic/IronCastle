using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.pqc.jcajce.provider.qtesla
{
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using Digest = org.bouncycastle.crypto.Digest;
	using Xof = org.bouncycastle.crypto.Xof;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using SHAKEDigest = org.bouncycastle.crypto.digests.SHAKEDigest;

	public class DigestUtil
	{
		internal static Digest getDigest(ASN1ObjectIdentifier oid)
		{
			if (oid.Equals(NISTObjectIdentifiers_Fields.id_sha256))
			{
				return new SHA256Digest();
			}
			if (oid.Equals(NISTObjectIdentifiers_Fields.id_sha512))
			{
				return new SHA512Digest();
			}
			if (oid.Equals(NISTObjectIdentifiers_Fields.id_shake128))
			{
				return new SHAKEDigest(128);
			}
			if (oid.Equals(NISTObjectIdentifiers_Fields.id_shake256))
			{
				return new SHAKEDigest(256);
			}

			throw new IllegalArgumentException("unrecognized digest OID: " + oid);
		}

		public static byte[] getDigestResult(Digest digest)
		{
			byte[] hash = new byte[DigestUtil.getDigestSize(digest)];

			if (digest is Xof)
			{
				((Xof)digest).doFinal(hash, 0, hash.Length);
			}
			else
			{
				digest.doFinal(hash, 0);
			}

			return hash;
		}

		public static int getDigestSize(Digest digest)
		{
			if (digest is Xof)
			{
				return digest.getDigestSize() * 2;
			}

			return digest.getDigestSize();
		}
	}

}