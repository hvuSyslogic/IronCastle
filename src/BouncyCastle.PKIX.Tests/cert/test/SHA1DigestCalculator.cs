using org.bouncycastle.asn1.oiw;

namespace org.bouncycastle.cert.test
{

	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Digest = org.bouncycastle.crypto.Digest;
	using SHA1Digest = org.bouncycastle.crypto.digests.SHA1Digest;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;


	public class SHA1DigestCalculator : DigestCalculator
	{
		private ByteArrayOutputStream bOut = new ByteArrayOutputStream();

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1);
		}

		public virtual OutputStream getOutputStream()
		{
			return bOut;
		}

		public virtual byte[] getDigest()
		{
			byte[] bytes = bOut.toByteArray();

			bOut.reset();

			Digest sha1 = new SHA1Digest();

			sha1.update(bytes, 0, bytes.Length);

			byte[] digest = new byte[sha1.getDigestSize()];

			sha1.doFinal(digest, 0);

			return digest;
		}
	}

}