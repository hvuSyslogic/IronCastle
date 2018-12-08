using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.agreement
{

	using ECDHUPrivateParameters = org.bouncycastle.crypto.@params.ECDHUPrivateParameters;
	using ECDHUPublicParameters = org.bouncycastle.crypto.@params.ECDHUPublicParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// EC Unified static/ephemeral agreement as described in NIST SP 800-56A using EC co-factor Diffie-Hellman.
	/// </summary>
	public class ECDHCUnifiedAgreement
	{
		private ECDHUPrivateParameters privParams;

		public virtual void init(CipherParameters key)
		{
			this.privParams = (ECDHUPrivateParameters)key;
		}

		public virtual int getFieldSize()
		{
			return (privParams.getStaticPrivateKey().getParameters().getCurve().getFieldSize() + 7) / 8;
		}

		public virtual byte[] calculateAgreement(CipherParameters pubKey)
		{
			ECDHUPublicParameters pubParams = (ECDHUPublicParameters)pubKey;

			ECDHCBasicAgreement sAgree = new ECDHCBasicAgreement();
			ECDHCBasicAgreement eAgree = new ECDHCBasicAgreement();

			sAgree.init(privParams.getStaticPrivateKey());

			BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

			eAgree.init(privParams.getEphemeralPrivateKey());

			BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

			return Arrays.concatenate(BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp), BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
		}
	}

}