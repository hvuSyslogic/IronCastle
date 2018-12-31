using org.bouncycastle.asn1;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.crypto;
using org.bouncycastle.crypto.digests;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.pqc.crypto.xmss
{

							
	public class DigestUtil
	{
		private static Map<string, ASN1ObjectIdentifier> nameToOid = new HashMap<string, ASN1ObjectIdentifier>();

		static DigestUtil()
		{
			nameToOid.put("SHA-256", NISTObjectIdentifiers_Fields.id_sha256);
			nameToOid.put("SHA-512", NISTObjectIdentifiers_Fields.id_sha512);
			nameToOid.put("SHAKE128", NISTObjectIdentifiers_Fields.id_shake128);
			nameToOid.put("SHAKE256", NISTObjectIdentifiers_Fields.id_shake256);
		}

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

		internal static ASN1ObjectIdentifier getDigestOID(string name)
		{
			ASN1ObjectIdentifier oid = nameToOid.get(name);
			if (oid != null)
			{
				return oid;
			}

			throw new IllegalArgumentException("unrecognized digest name: " + name);
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