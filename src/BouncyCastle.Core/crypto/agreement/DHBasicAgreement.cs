using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.agreement
{

	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;
	using DHPrivateKeyParameters = org.bouncycastle.crypto.@params.DHPrivateKeyParameters;
	using DHPublicKeyParameters = org.bouncycastle.crypto.@params.DHPublicKeyParameters;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;

	/// <summary>
	/// a Diffie-Hellman key agreement class.
	/// <para>
	/// note: This is only the basic algorithm, it doesn't take advantage of
	/// long term public keys if they are available. See the DHAgreement class
	/// for a "better" implementation.
	/// </para>
	/// </summary>
	public class DHBasicAgreement : BasicAgreement
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private DHPrivateKeyParameters key;
		private DHParameters dhParams;

		public virtual void init(CipherParameters param)
		{
			AsymmetricKeyParameter kParam;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;
				kParam = (AsymmetricKeyParameter)rParam.getParameters();
			}
			else
			{
				kParam = (AsymmetricKeyParameter)param;
			}

			if (!(kParam is DHPrivateKeyParameters))
			{
				throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
			}

			this.key = (DHPrivateKeyParameters)kParam;
			this.dhParams = key.getParameters();
		}

		public virtual int getFieldSize()
		{
			return (key.getParameters().getP().bitLength() + 7) / 8;
		}

		/// <summary>
		/// given a short term public key from a given party calculate the next
		/// message in the agreement sequence. 
		/// </summary>
		public virtual BigInteger calculateAgreement(CipherParameters pubKey)
		{
			DHPublicKeyParameters pub = (DHPublicKeyParameters)pubKey;

			if (!pub.getParameters().Equals(dhParams))
			{
				throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
			}

			BigInteger p = dhParams.getP();

			BigInteger peerY = pub.getY();
			if (peerY == null || peerY.compareTo(ONE) <= 0 || peerY.compareTo(p.subtract(ONE)) >= 0)
			{
				throw new IllegalArgumentException("Diffie-Hellman public key is weak");
			}

			BigInteger result = peerY.modPow(key.getX(), p);
			if (result.Equals(ONE))
			{
				throw new IllegalStateException("Shared key can't be 1");
			}

			return result;
		}
	}

}