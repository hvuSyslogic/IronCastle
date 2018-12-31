using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.generators;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.agreement
{

							
	/// <summary>
	/// a Diffie-Hellman key exchange engine.
	/// <para>
	/// note: This uses MTI/A0 key agreement in order to make the key agreement
	/// secure against passive attacks. If you're doing Diffie-Hellman and both
	/// parties have long term public keys you should look at using this. For
	/// further information have a look at RFC 2631.
	/// </para>
	/// <para>
	/// It's possible to extend this to more than two parties as well, for the moment
	/// that is left as an exercise for the reader.
	/// </para>
	/// </summary>
	public class DHAgreement
	{
		private static readonly BigInteger ONE = BigInteger.valueOf(1);

		private DHPrivateKeyParameters key;
		private DHParameters dhParams;
		private BigInteger privateValue;
		private SecureRandom random;

		public virtual void init(CipherParameters param)
		{
			AsymmetricKeyParameter kParam;

			if (param is ParametersWithRandom)
			{
				ParametersWithRandom rParam = (ParametersWithRandom)param;

				this.random = rParam.getRandom();
				kParam = (AsymmetricKeyParameter)rParam.getParameters();
			}
			else
			{
				this.random = CryptoServicesRegistrar.getSecureRandom();
				kParam = (AsymmetricKeyParameter)param;
			}


			if (!(kParam is DHPrivateKeyParameters))
			{
				throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
			}

			this.key = (DHPrivateKeyParameters)kParam;
			this.dhParams = key.getParameters();
		}

		/// <summary>
		/// calculate our initial message.
		/// </summary>
		public virtual BigInteger calculateMessage()
		{
			DHKeyPairGenerator dhGen = new DHKeyPairGenerator();
			dhGen.init(new DHKeyGenerationParameters(random, dhParams));
			AsymmetricCipherKeyPair dhPair = dhGen.generateKeyPair();

			this.privateValue = ((DHPrivateKeyParameters)dhPair.getPrivate()).getX();

			return ((DHPublicKeyParameters)dhPair.getPublic()).getY();
		}

		/// <summary>
		/// given a message from a given party and the corresponding public key,
		/// calculate the next message in the agreement sequence. In this case
		/// this will represent the shared secret.
		/// </summary>
		public virtual BigInteger calculateAgreement(DHPublicKeyParameters pub, BigInteger message)
		{
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

			BigInteger result = peerY.modPow(privateValue, p);
			if (result.Equals(ONE))
			{
				throw new IllegalStateException("Shared key can't be 1");
			}

			return message.modPow(key.getX(), p).multiply(result).mod(p);
		}
	}

}