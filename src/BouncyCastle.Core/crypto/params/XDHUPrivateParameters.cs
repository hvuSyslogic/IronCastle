using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{

	/// <summary>
	/// Parameters holder for private unified static/ephemeral agreement using Edwards Curves.
	/// </summary>
	public class XDHUPrivateParameters : CipherParameters
	{
		private AsymmetricKeyParameter staticPrivateKey;
		private AsymmetricKeyParameter ephemeralPrivateKey;
		private AsymmetricKeyParameter ephemeralPublicKey;

		public XDHUPrivateParameters(AsymmetricKeyParameter staticPrivateKey, AsymmetricKeyParameter ephemeralPrivateKey) : this(staticPrivateKey, ephemeralPrivateKey, null)
		{
		}

		public XDHUPrivateParameters(AsymmetricKeyParameter staticPrivateKey, AsymmetricKeyParameter ephemeralPrivateKey, AsymmetricKeyParameter ephemeralPublicKey)
		{
			if (staticPrivateKey == null)
			{
				throw new NullPointerException("staticPrivateKey cannot be null");
			}
			if (!(staticPrivateKey is X448PrivateKeyParameters || staticPrivateKey is X25519PrivateKeyParameters))
			{
				throw new IllegalArgumentException("only X25519 and X448 paramaters can be used");
			}
			if (ephemeralPrivateKey == null)
			{
				throw new NullPointerException("ephemeralPrivateKey cannot be null");
			}

			if (!staticPrivateKey.GetType().IsInstanceOfType(ephemeralPrivateKey))
			{
				throw new IllegalArgumentException("static and ephemeral private keys have different domain parameters");
			}

			if (ephemeralPublicKey == null)
			{
				if (ephemeralPrivateKey is X448PrivateKeyParameters)
				{
					ephemeralPublicKey = ((X448PrivateKeyParameters)ephemeralPrivateKey).generatePublicKey();
				}
				else
				{
					ephemeralPublicKey = ((X25519PrivateKeyParameters)ephemeralPrivateKey).generatePublicKey();
				}
			}
			else
			{
				if (ephemeralPublicKey is X448PublicKeyParameters && !(staticPrivateKey is X448PrivateKeyParameters))
				{
					throw new IllegalArgumentException("ephemeral public key has different domain parameters");
				}
				if (ephemeralPublicKey is X25519PublicKeyParameters && !(staticPrivateKey is X25519PrivateKeyParameters))
				{
					throw new IllegalArgumentException("ephemeral public key has different domain parameters");
				}
			}

			this.staticPrivateKey = staticPrivateKey;
			this.ephemeralPrivateKey = ephemeralPrivateKey;
			this.ephemeralPublicKey = ephemeralPublicKey;
		}

		public virtual AsymmetricKeyParameter getStaticPrivateKey()
		{
			return staticPrivateKey;
		}

		public virtual AsymmetricKeyParameter getEphemeralPrivateKey()
		{
			return ephemeralPrivateKey;
		}

		public virtual AsymmetricKeyParameter getEphemeralPublicKey()
		{
			return ephemeralPublicKey;
		}
	}

}