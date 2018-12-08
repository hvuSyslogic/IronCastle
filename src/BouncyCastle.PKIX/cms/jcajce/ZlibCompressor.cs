namespace org.bouncycastle.cms.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using OutputCompressor = org.bouncycastle.@operator.OutputCompressor;

	public class ZlibCompressor : OutputCompressor
	{
		private const string ZLIB = "1.2.840.113549.1.9.16.3.8";

		public virtual AlgorithmIdentifier getAlgorithmIdentifier()
		{
			return new AlgorithmIdentifier(new ASN1ObjectIdentifier(ZLIB));
		}

		public virtual OutputStream getOutputStream(OutputStream comOut)
		{
			return new DeflaterOutputStream(comOut);
		}
	}

}