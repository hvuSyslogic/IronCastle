using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.agreement
{

	using DHUPrivateParameters = org.bouncycastle.crypto.@params.DHUPrivateParameters;
	using DHUPublicParameters = org.bouncycastle.crypto.@params.DHUPublicParameters;
	using Arrays = org.bouncycastle.util.Arrays;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	/// <summary>
	/// FFC Unified static/ephemeral agreement as described in NIST SP 800-56A.
	/// </summary>
	public class DHUnifiedAgreement
	{
		private DHUPrivateParameters privParams;

		public virtual void init(CipherParameters key)
		{
			this.privParams = (DHUPrivateParameters)key;
		}

		public virtual int getFieldSize()
		{
			return (privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
		}

		public virtual byte[] calculateAgreement(CipherParameters pubKey)
		{
			DHUPublicParameters pubParams = (DHUPublicParameters)pubKey;

			DHBasicAgreement sAgree = new DHBasicAgreement();
			DHBasicAgreement eAgree = new DHBasicAgreement();

			sAgree.init(privParams.getStaticPrivateKey());

			BigInteger sComp = sAgree.calculateAgreement(pubParams.getStaticPublicKey());

			eAgree.init(privParams.getEphemeralPrivateKey());

			BigInteger eComp = eAgree.calculateAgreement(pubParams.getEphemeralPublicKey());

			return Arrays.concatenate(BigIntegers.asUnsignedByteArray(this.getFieldSize(), eComp), BigIntegers.asUnsignedByteArray(this.getFieldSize(), sComp));
		}
	}

}