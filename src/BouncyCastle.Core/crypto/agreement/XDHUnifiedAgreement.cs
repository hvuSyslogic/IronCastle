using org.bouncycastle.crypto.@params;

namespace org.bouncycastle.crypto.agreement
{
		
	public class XDHUnifiedAgreement : RawAgreement
	{
		private readonly RawAgreement xAgreement;

		private XDHUPrivateParameters privParams;

		public XDHUnifiedAgreement(RawAgreement xAgreement)
		{
			this.xAgreement = xAgreement;
		}

		public virtual void init(CipherParameters key)
		{
			this.privParams = (XDHUPrivateParameters)key;
		}

		public virtual int getAgreementSize()
		{
			return xAgreement.getAgreementSize() * 2;
		}

		public virtual void calculateAgreement(CipherParameters publicKey, byte[] buf, int off)
		{
			XDHUPublicParameters pubParams = (XDHUPublicParameters)publicKey;

			xAgreement.init(privParams.getEphemeralPrivateKey());

			xAgreement.calculateAgreement(pubParams.getEphemeralPublicKey(), buf, off);

			xAgreement.init(privParams.getStaticPrivateKey());

			xAgreement.calculateAgreement(pubParams.getStaticPublicKey(), buf, off + xAgreement.getAgreementSize());
		}
	}

}