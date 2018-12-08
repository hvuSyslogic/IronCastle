using org.bouncycastle.asn1.nist;

namespace org.bouncycastle.tsp.test
{

	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;


	public class SHA256DigestCalculator : DigestCalculator
	{
		private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha256);
		}

		public virtual OutputStream getOutputStream()
		{
			return bOut;
		}

		public virtual byte[] getDigest()
		{
			byte[] bytes = bOut.toByteArray();

			bOut.reset();

			Digest sha256 = new SHA256Digest();

			sha256.update(bytes, 0, bytes.Length);

			byte[] digest = new byte[sha256.getDigestSize()];

			sha256.doFinal(digest, 0);

			return digest;
		}
	}

}