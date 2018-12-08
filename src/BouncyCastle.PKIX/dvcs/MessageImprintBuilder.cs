using System;

namespace org.bouncycastle.dvcs
{

	using DigestInfo = org.bouncycastle.asn1.x509.DigestInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;

	public class MessageImprintBuilder
	{
		private readonly DigestCalculator digestCalculator;

		public MessageImprintBuilder(DigestCalculator digestCalculator)
		{
			this.digestCalculator = digestCalculator;
		}

		public virtual MessageImprint build(byte[] message)
		{
			try
			{
				OutputStream dOut = digestCalculator.getOutputStream();

				dOut.write(message);

				dOut.close();

				return new MessageImprint(new DigestInfo(digestCalculator.getAlgorithmIdentifier(), digestCalculator.getDigest()));
			}
			catch (Exception e)
			{
				throw new DVCSException("unable to build MessageImprint: " + e.Message, e);
			}
		}
	}

}