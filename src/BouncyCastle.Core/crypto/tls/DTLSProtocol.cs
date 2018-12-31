using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.tls
{

	
	public abstract class DTLSProtocol
	{
		protected internal readonly SecureRandom secureRandom;

		public DTLSProtocol(SecureRandom secureRandom)
		{
			if (secureRandom == null)
			{
				throw new IllegalArgumentException("'secureRandom' cannot be null");
			}

			this.secureRandom = secureRandom;
		}

		public virtual void processFinished(byte[] body, byte[] expected_verify_data)
		{
			ByteArrayInputStream buf = new ByteArrayInputStream(body);

			byte[] verify_data = TlsUtils.readFully(expected_verify_data.Length, buf);

			TlsProtocol.assertEmpty(buf);

			if (!Arrays.constantTimeAreEqual(expected_verify_data, verify_data))
			{
				throw new TlsFatalAlert(AlertDescription.handshake_failure);
			}
		}

		protected internal static void applyMaxFragmentLengthExtension(DTLSRecordLayer recordLayer, short maxFragmentLength)
		{
			if (maxFragmentLength >= 0)
			{
				if (!MaxFragmentLength.isValid(maxFragmentLength))
				{
					throw new TlsFatalAlert(AlertDescription.internal_error);
				}

				int plainTextLimit = 1 << (8 + maxFragmentLength);
				recordLayer.setPlaintextLimit(plainTextLimit);
			}
		}

		protected internal static short evaluateMaxFragmentLengthExtension(bool resumedSession, Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription)
		{
			short maxFragmentLength = TlsExtensionsUtils.getMaxFragmentLengthExtension(serverExtensions);
			if (maxFragmentLength >= 0)
			{
				if (!MaxFragmentLength.isValid(maxFragmentLength) || (!resumedSession && maxFragmentLength != TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions)))
				{
					throw new TlsFatalAlert(alertDescription);
				}
			}
			return maxFragmentLength;
		}

		protected internal static byte[] generateCertificate(Certificate certificate)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			certificate.encode(buf);
			return buf.toByteArray();
		}

		protected internal static byte[] generateSupplementalData(Vector supplementalData)
		{
			ByteArrayOutputStream buf = new ByteArrayOutputStream();
			TlsProtocol.writeSupplementalData(buf, supplementalData);
			return buf.toByteArray();
		}

		protected internal static void validateSelectedCipherSuite(int selectedCipherSuite, short alertDescription)
		{
			switch (TlsUtils.getEncryptionAlgorithm(selectedCipherSuite))
			{
			case EncryptionAlgorithm.RC4_40:
			case EncryptionAlgorithm.RC4_128:
				throw new TlsFatalAlert(alertDescription);
			}
		}
	}

}