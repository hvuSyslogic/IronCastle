namespace org.bouncycastle.openpgp.examples
{

	using JcaKeyFingerprintCalculator = org.bouncycastle.openpgp.@operator.jcajce.JcaKeyFingerprintCalculator;
	using JcePBESecretKeyDecryptorBuilder = org.bouncycastle.openpgp.@operator.jcajce.JcePBESecretKeyDecryptorBuilder;

	public class PGPExampleUtil
	{
		internal static byte[] compressFile(string fileName, int algorithm)
		{
			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
			PGPUtil.writeFileToLiteralData(comData.open(bOut), PGPLiteralData.BINARY, new File(fileName));
			comData.close();
			return bOut.toByteArray();
		}

		/// <summary>
		/// Search a secret key ring collection for a secret key corresponding to keyID if it
		/// exists.
		/// </summary>
		/// <param name="pgpSec"> a secret key ring collection. </param>
		/// <param name="keyID"> keyID we want. </param>
		/// <param name="pass"> passphrase to decrypt secret key with. </param>
		/// <returns> the private key. </returns>
		/// <exception cref="PGPException"> </exception>
		/// <exception cref="NoSuchProviderException"> </exception>
		internal static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
		{
			PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

			if (pgpSecKey == null)
			{
				return null;
			}

			return pgpSecKey.extractPrivateKey((new JcePBESecretKeyDecryptorBuilder()).setProvider("BC").build(pass));
		}

		internal static PGPPublicKey readPublicKey(string fileName)
		{
			InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
			PGPPublicKey pubKey = readPublicKey(keyIn);
			keyIn.close();
			return pubKey;
		}

		/// <summary>
		/// A simple routine that opens a key ring file and loads the first available key
		/// suitable for encryption.
		/// </summary>
		/// <param name="input"> data stream containing the public key data </param>
		/// <returns> the first public key found. </returns>
		/// <exception cref="IOException"> </exception>
		/// <exception cref="PGPException"> </exception>
		internal static PGPPublicKey readPublicKey(InputStream input)
		{
			PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

			//
			// we just loop through the collection till we find a key suitable for encryption, in the real
			// world you would probably want to be a bit smarter about this.
			//

			Iterator keyRingIter = pgpPub.getKeyRings();
			while (keyRingIter.hasNext())
			{
				PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

				Iterator keyIter = keyRing.getPublicKeys();
				while (keyIter.hasNext())
				{
					PGPPublicKey key = (PGPPublicKey)keyIter.next();

					if (key.isEncryptionKey())
					{
						return key;
					}
				}
			}

			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}

		internal static PGPSecretKey readSecretKey(string fileName)
		{
			InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
			PGPSecretKey secKey = readSecretKey(keyIn);
			keyIn.close();
			return secKey;
		}

		/// <summary>
		/// A simple routine that opens a key ring file and loads the first available key
		/// suitable for signature generation.
		/// </summary>
		/// <param name="input"> stream to read the secret key ring collection from. </param>
		/// <returns> a secret key. </returns>
		/// <exception cref="IOException"> on a problem with using the input stream. </exception>
		/// <exception cref="PGPException"> if there is an issue parsing the input stream. </exception>
		internal static PGPSecretKey readSecretKey(InputStream input)
		{
			PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

			//
			// we just loop through the collection till we find a key suitable for encryption, in the real
			// world you would probably want to be a bit smarter about this.
			//

			Iterator keyRingIter = pgpSec.getKeyRings();
			while (keyRingIter.hasNext())
			{
				PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();

				Iterator keyIter = keyRing.getSecretKeys();
				while (keyIter.hasNext())
				{
					PGPSecretKey key = (PGPSecretKey)keyIter.next();

					if (key.isSigningKey())
					{
						return key;
					}
				}
			}

			throw new IllegalArgumentException("Can't find signing key in key ring.");
		}
	}

}