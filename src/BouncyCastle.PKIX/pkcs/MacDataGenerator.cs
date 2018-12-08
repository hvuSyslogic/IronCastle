using System;

namespace org.bouncycastle.pkcs
{


	using MacData = org.bouncycastle.asn1.pkcs.MacData;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;

	public class MacDataGenerator
	{
		private PKCS12MacCalculatorBuilder builder;

		public MacDataGenerator(PKCS12MacCalculatorBuilder builder)
		{
			this.builder = builder;
		}

		public virtual MacData build(char[] password, byte[] data)
		{
			MacCalculator macCalculator;

			try
			{
				macCalculator = builder.build(password);

				OutputStream @out = macCalculator.getOutputStream();

				@out.write(data);

				@out.close();
			}
			catch (Exception e)
			{
				throw new PKCSException("unable to process data: " + e.Message, e);
			}

			AlgorithmIdentifier algId = macCalculator.getAlgorithmIdentifier();

			DigestInfo dInfo = new DigestInfo(builder.getDigestAlgorithmIdentifier(), macCalculator.getMac());
			PKCS12PBEParams @params = PKCS12PBEParams.getInstance(algId.getParameters());

			return new MacData(dInfo, @params.getIV(), @params.getIterations().intValue());
		}
	}

}