using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.qtesla
{

	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using CryptoServicesRegistrar = CryptoServicesRegistrar;
	using ParametersWithRandom = org.bouncycastle.crypto.@params.ParametersWithRandom;

	/// <summary>
	/// Signer for the qTESLA algorithm (https://qtesla.org/)
	/// </summary>
	public class QTESLASigner : MessageSigner
	{
		/// <summary>
		/// The Public Key of the Identity Whose Signature Will be Generated
		/// </summary>
		private QTESLAPublicKeyParameters publicKey;

		/// <summary>
		/// The Private Key of the Identity Whose Signature Will be Generated
		/// </summary>
		private QTESLAPrivateKeyParameters privateKey;

		/// <summary>
		/// The Source of Randomness for private key operations
		/// </summary>
		private SecureRandom secureRandom;

		public QTESLASigner()
		{
		}

		/// <summary>
		/// Initialise the signer.
		/// </summary>
		/// <param name="forSigning"> true if we are generating a signature, false
		///                   otherwise. </param>
		/// <param name="param">      ParametersWithRandom containing a private key for signature generation, public key otherwise. </param>
		public virtual void init(bool forSigning, CipherParameters param)
		{
			 if (forSigning)
			 {
				 if (param is ParametersWithRandom)
				 {
					 this.secureRandom = ((ParametersWithRandom)param).getRandom();
					 privateKey = (QTESLAPrivateKeyParameters)((ParametersWithRandom)param).getParameters();
				 }
				 else
				 {
					 this.secureRandom = CryptoServicesRegistrar.getSecureRandom();
					 privateKey = (QTESLAPrivateKeyParameters)param;
				 }
				 publicKey = null;
				 QTESLASecurityCategory.validate(privateKey.getSecurityCategory());
			 }
			 else
			 {
				 privateKey = null;
				 publicKey = (QTESLAPublicKeyParameters)param;
				 QTESLASecurityCategory.validate(publicKey.getSecurityCategory());
			 }
		}

		/// <summary>
		/// Generate a signature directly for the passed in message.
		/// </summary>
		/// <param name="message"> the message to be signed. </param>
		/// <returns> the signature generated. </returns>
		public virtual byte[] generateSignature(byte[] message)
		{
			byte[] sig = new byte[QTESLASecurityCategory.getSignatureSize(privateKey.getSecurityCategory())];

			switch (privateKey.getSecurityCategory())
			{
			case QTESLASecurityCategory.HEURISTIC_I:
				QTESLA.signingI(sig, message, 0, message.Length, privateKey.getSecret(), secureRandom);
				break;
			case QTESLASecurityCategory.HEURISTIC_III_SIZE:
				QTESLA.signingIIISize(sig, message, 0, message.Length, privateKey.getSecret(), secureRandom);
				break;
			case QTESLASecurityCategory.HEURISTIC_III_SPEED:
				QTESLA.signingIIISpeed(sig, message, 0, message.Length, privateKey.getSecret(), secureRandom);
				break;
			case QTESLASecurityCategory.PROVABLY_SECURE_I:
				QTESLA.signingIP(sig, message, 0, message.Length, privateKey.getSecret(), secureRandom);
				break;
			case QTESLASecurityCategory.PROVABLY_SECURE_III:
				QTESLA.signingIIIP(sig, message, 0, message.Length, privateKey.getSecret(), secureRandom);
				break;
			default:
				throw new IllegalArgumentException("unknown security category: " + privateKey.getSecurityCategory());
			}

			return sig;
		}

		/// <summary>
		/// Verify the signature against the passed in message.
		/// </summary>
		/// <param name="message"> the message that was supposed to have been signed. </param>
		/// <param name="signature"> the signature of the message </param>
		/// <returns> true if the signature passes, false otherwise. </returns>
		public virtual bool verifySignature(byte[] message, byte[] signature)
		{
			int status;

			switch (publicKey.getSecurityCategory())
			{
			case QTESLASecurityCategory.HEURISTIC_I:
				status = QTESLA.verifyingI(message, signature, 0, signature.Length, publicKey.getPublicData());
				break;
			case QTESLASecurityCategory.HEURISTIC_III_SIZE:
				status = QTESLA.verifyingIIISize(message, signature, 0, signature.Length, publicKey.getPublicData());
				break;
			case QTESLASecurityCategory.HEURISTIC_III_SPEED:
				status = QTESLA.verifyingIIISpeed(message, signature, 0, signature.Length, publicKey.getPublicData());
				break;
			case QTESLASecurityCategory.PROVABLY_SECURE_I:
				status = QTESLA.verifyingPI(message, signature, 0, signature.Length, publicKey.getPublicData());
				break;
			case QTESLASecurityCategory.PROVABLY_SECURE_III:
				status = QTESLA.verifyingPIII(message, signature, 0, signature.Length, publicKey.getPublicData());
				break;
			default:
				throw new IllegalArgumentException("unknown security category: " + publicKey.getSecurityCategory());
			}

			return 0 == status;
		}
	}

}