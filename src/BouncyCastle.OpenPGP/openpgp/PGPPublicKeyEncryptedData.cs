using org.bouncycastle.bcpg;

using System;

namespace org.bouncycastle.openpgp
{

	using BCPGInputStream = org.bouncycastle.bcpg.BCPGInputStream;
	using InputStreamPacket = org.bouncycastle.bcpg.InputStreamPacket;
	using PublicKeyEncSessionPacket = org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
	using SymmetricEncIntegrityPacket = org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
	using SymmetricKeyAlgorithmTags = org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
	using PGPDataDecryptor = org.bouncycastle.openpgp.@operator.PGPDataDecryptor;
	using PublicKeyDataDecryptorFactory = org.bouncycastle.openpgp.@operator.PublicKeyDataDecryptorFactory;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;

	/// <summary>
	/// A public key encrypted data object.
	/// </summary>
	public class PGPPublicKeyEncryptedData : PGPEncryptedData
	{
		internal PublicKeyEncSessionPacket keyData;

		public PGPPublicKeyEncryptedData(PublicKeyEncSessionPacket keyData, InputStreamPacket encData) : base(encData)
		{

			this.keyData = keyData;
		}

		private bool confirmCheckSum(byte[] sessionInfo)
		{
			int check = 0;

			for (int i = 1; i != sessionInfo.Length - 2; i++)
			{
				check += sessionInfo[i] & 0xff;
			}

			return (sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8)) && (sessionInfo[sessionInfo.Length - 1] == (byte)(check));
		}

		/// <summary>
		/// Return the keyID for the key used to encrypt the data.
		/// </summary>
		/// <returns> long </returns>
		public virtual long getKeyID()
		{
			return keyData.getKeyID();
		}

		/// <summary>
		/// Return the symmetric key algorithm required to decrypt the data protected by this object.
		/// </summary>
		/// <param name="dataDecryptorFactory"> decryptor factory to use to recover the session data. </param>
		/// <returns> the identifier of the <seealso cref="SymmetricKeyAlgorithmTags encryption algorithm"/> used to
		///         encrypt this object. </returns>
		/// <exception cref="PGPException"> if the session data cannot be recovered. </exception>
		public virtual int getSymmetricAlgorithm(PublicKeyDataDecryptorFactory dataDecryptorFactory)
		{
			byte[] plain = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());

			return plain[0];
		}

		/// <summary>
		/// Open an input stream which will provide the decrypted data protected by this object.
		/// </summary>
		/// <param name="dataDecryptorFactory">  decryptor factory to use to recover the session data and provide the stream. </param>
		/// <returns>  the resulting input stream </returns>
		/// <exception cref="PGPException">  if the session data cannot be recovered or the stream cannot be created. </exception>
		public virtual InputStream getDataStream(PublicKeyDataDecryptorFactory dataDecryptorFactory)
		{
			byte[] sessionData = dataDecryptorFactory.recoverSessionData(keyData.getAlgorithm(), keyData.getEncSessionKey());

			if (!confirmCheckSum(sessionData))
			{
				throw new PGPKeyValidationException("key checksum failed");
			}

			if (sessionData[0] != SymmetricKeyAlgorithmTags_Fields.NULL)
			{
				try
				{
					bool withIntegrityPacket = encData is SymmetricEncIntegrityPacket;
					byte[] sessionKey = new byte[sessionData.Length - 3];

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

					//
					// some versions of PGP appear to produce 0 for the extra
					// bytes rather than repeating the two previous bytes
					//
					/*
					             * Commented out in the light of the oracle attack.
					            if (iv[iv.length - 2] != (byte)v1 && v1 != 0)
					            {
					                throw new PGPDataValidationException("data check failed.");
					            }
	
					            if (iv[iv.length - 1] != (byte)v2 && v2 != 0)
					            {
					                throw new PGPDataValidationException("data check failed.");
					            }
					            */

					return encStream;
				}
				catch (PGPException e)
				{
					throw e;
				}
				catch (Exception e)
				{
					throw new PGPException("Exception starting decryption", e);
				}
			}
			else
			{
				return encData.getInputStream();
			}
		}
	}

}