using org.bouncycastle.asn1;

namespace org.bouncycastle.cert.crmf
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using PBMParameter = org.bouncycastle.asn1.cmp.PBMParameter;
	using PKMACValue = org.bouncycastle.asn1.crmf.PKMACValue;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using Arrays = org.bouncycastle.util.Arrays;

	public class PKMACValueVerifier
	{
		private readonly PKMACBuilder builder;

		public PKMACValueVerifier(PKMACBuilder builder)
		{
			this.builder = builder;
		}

		public virtual bool isValid(PKMACValue value, char[] password, SubjectPublicKeyInfo keyInfo)
		{
			builder.setParameters(PBMParameter.getInstance(value.getAlgId().getParameters()));
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

			return Arrays.areEqual(calculator.getMac(), value.getValue().getBytes());
		}
	}
}