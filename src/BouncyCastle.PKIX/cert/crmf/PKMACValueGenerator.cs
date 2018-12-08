using org.bouncycastle.asn1;

namespace org.bouncycastle.cert.crmf
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using PKMACValue = org.bouncycastle.asn1.crmf.PKMACValue;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;

	public class PKMACValueGenerator
	{
		private PKMACBuilder builder;

		public PKMACValueGenerator(PKMACBuilder builder)
		{
			this.builder = builder;
		}

		public virtual PKMACValue generate(char[] password, SubjectPublicKeyInfo keyInfo)
		{
			MacCalculator calculator = builder.build(password);

			OutputStream macOut = calculator.getOutputStream();

			try
			{
				macOut.write(keyInfo.getEncoded(ASN1Encoding_Fields.DER));

				macOut.close();
			}
			catch (IOException e)
			{
				throw new CRMFException("exception encoding mac input: " + e.Message, e);
			}

			return new PKMACValue(calculator.getAlgorithmIdentifier(), new DERBitString(calculator.getMac()));
		}
	}

}