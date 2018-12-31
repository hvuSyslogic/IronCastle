using BouncyCastle.Core.Port;
using org.bouncycastle.crypto;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.qtesla
{

			
	/// <summary>
	/// Key-pair generator for qTESLA keys.
	/// </summary>
	public sealed class QTESLAKeyPairGenerator : AsymmetricCipherKeyPairGenerator
	{
		/// <summary>
		/// qTESLA Security Category
		/// </summary>
		private int securityCategory;
		private SecureRandom secureRandom;

		/// <summary>
		/// Initialize the generator with a security category and a source of randomness.
		/// </summary>
		/// <param name="param"> a <seealso cref="QTESLAKeyGenerationParameters"/> object. </param>
		public void init(KeyGenerationParameters param)
		{
			QTESLAKeyGenerationParameters parameters = (QTESLAKeyGenerationParameters)param;

			this.secureRandom = parameters.getRandom();
			this.securityCategory = parameters.getSecurityCategory();
		}

		/// <summary>
		/// Generate a key-pair.
		/// </summary>
		/// <returns> a matching key-pair consisting of (QTESLAPublicKeyParameters, QTESLAPrivateKeyParameters). </returns>
		public AsymmetricCipherKeyPair generateKeyPair()
		{
			byte[] privateKey = allocatePrivate(securityCategory);
			byte[] publicKey = allocatePublic(securityCategory);

			switch (securityCategory)
			{
			case QTESLASecurityCategory.HEURISTIC_I:
				QTESLA.generateKeyPairI(publicKey, privateKey, secureRandom);
				break;
			case QTESLASecurityCategory.HEURISTIC_III_SIZE:
				QTESLA.generateKeyPairIIISize(publicKey, privateKey, secureRandom);
				break;
			case QTESLASecurityCategory.HEURISTIC_III_SPEED:
				QTESLA.generateKeyPairIIISpeed(publicKey, privateKey, secureRandom);
				break;
			case QTESLASecurityCategory.PROVABLY_SECURE_I:
				QTESLA.generateKeyPairIP(publicKey, privateKey, secureRandom);
				break;
			case QTESLASecurityCategory.PROVABLY_SECURE_III:
				QTESLA.generateKeyPairIIIP(publicKey, privateKey, secureRandom);
				break;
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}

			return new AsymmetricCipherKeyPair(new QTESLAPublicKeyParameters(securityCategory, publicKey), new QTESLAPrivateKeyParameters(securityCategory, privateKey));
		}

		private byte[] allocatePrivate(int securityCategory)
		{
			return new byte[QTESLASecurityCategory.getPrivateSize(securityCategory)];
		}

		private byte[] allocatePublic(int securityCategory)
		{
			return new byte[QTESLASecurityCategory.getPublicSize(securityCategory)];
		}
	}

}