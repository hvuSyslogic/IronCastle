using System;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using InputStreamPacket = org.bouncycastle.bcpg.InputStreamPacket;
	using SymmetricEncIntegrityPacket = org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using SymmetricKeyEncSessionPacket = org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
	using PBEDataDecryptorFactory = org.bouncycastle.openpgp.@operator.PBEDataDecryptorFactory;
	using PGPDataDecryptor = org.bouncycastle.openpgp.@operator.PGPDataDecryptor;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;

	/// <summary>
	/// A password based encryption object.
	/// <para>
	/// PBE encrypted data objects can be <seealso cref="#getDataStream(PBEDataDecryptorFactory) decrypted "/>
	/// using a <seealso cref="PBEDataDecryptorFactory"/>.
	/// </para>
	/// </summary>
	public class PGPPBEEncryptedData : PGPEncryptedData
	{
		internal SymmetricKeyEncSessionPacket keyData;

		/// <summary>
		/// Construct a PBE encryped data object.
		/// </summary>
		/// <param name="keyData"> the PBE key data packet associated with the encrypted data in the PGP object
		///            stream. </param>
		/// <param name="encData"> the encrypted data. </param>
		public PGPPBEEncryptedData(SymmetricKeyEncSessionPacket keyData, InputStreamPacket encData) : base(encData)
		{

			this.keyData = keyData;
		}

		/// <summary>
		/// Return the symmetric key algorithm required to decrypt the data protected by this object.
		/// </summary>
		/// <param name="dataDecryptorFactory"> decryptor factory to use to recover the session data. </param>
		/// <returns> the identifier of the <seealso cref="SymmetricKeyAlgorithmTags encryption algorithm"/> used to
		///         encrypt this object. </returns>
		/// <exception cref="PGPException"> if the session data cannot be recovered. </exception>
		public virtual int getSymmetricAlgorithm(PBEDataDecryptorFactory dataDecryptorFactory)
		{
			byte[] key = dataDecryptorFactory.makeKeyFromPassPhrase(keyData.getEncAlgorithm(), keyData.getS2K());
			byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());

			return sessionData[0];
		}

		/// <summary>
		/// Open an input stream which will provide the decrypted data protected by this object.
		/// </summary>
		/// <param name="dataDecryptorFactory"> decryptor factory to use to recover the session data and provide
		///            the stream. </param>
		/// <returns> the resulting decrypted input stream, probably containing a sequence of PGP data
		///         objects. </returns>
		/// <exception cref="PGPException"> if the session data cannot be recovered or the stream cannot be created. </exception>
		public virtual InputStream getDataStream(PBEDataDecryptorFactory dataDecryptorFactory)
		{
			try
			{
				int keyAlgorithm = keyData.getEncAlgorithm();
				byte[] key = dataDecryptorFactory.makeKeyFromPassPhrase(keyAlgorithm, keyData.getS2K());
				bool withIntegrityPacket = encData is SymmetricEncIntegrityPacket;

				byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getEncAlgorithm(), key, keyData.getSecKeyData());
				byte[] sessionKey = new byte[sessionData.Length - 1];

				JavaSystem.arraycopy(sessionData, 1, sessionKey, 0, sessionKey.Length);

				PGPDataDecryptor dataDecryptor = dataDecryptorFactory.createDataDecryptor(withIntegrityPacket, sessionData[0] & 0xff, sessionKey);

				encStream = new BCPGInputStream(dataDecryptor.getInputStream(encData.getInputStream()));

				if (withIntegrityPacket)
				{
					truncStream = new TruncatedStream(this, encStream);

					integrityCalculator = dataDecryptor.getIntegrityCalculator();

					encStream = new TeeInputStream(truncStream, integrityCalculator.getOutputStream());
				}

				byte[] iv = new byte[dataDecryptor.getBlockSize()];
				for (int i = 0; i != iv.Length; i++)
				{
					int ch = encStream.read();

					if (ch < 0)
					{
						throw new EOFException("unexpected end of stream.");
					}

					iv[i] = (byte)ch;
				}

				int v1 = encStream.read();
				int v2 = encStream.read();

				if (v1 < 0 || v2 < 0)
				{
					throw new EOFException("unexpected end of stream.");
				}


				// Note: the oracle attack on "quick check" bytes is not deemed
				// a security risk for PBE (see PGPPublicKeyEncryptedData)

				bool repeatCheckPassed = iv[iv.Length - 2] == (byte) v1 && iv[iv.Length - 1] == (byte) v2;

				// Note: some versions of PGP appear to produce 0 for the extra
				// bytes rather than repeating the two previous bytes
				bool zeroesCheckPassed = v1 == 0 && v2 == 0;

				if (!repeatCheckPassed && !zeroesCheckPassed)
				{
					throw new PGPDataValidationException("data check failed.");
				}

				return encStream;
			}
			catch (PGPException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				throw new PGPException("Exception creating cipher", e);
			}
		}
	}

}