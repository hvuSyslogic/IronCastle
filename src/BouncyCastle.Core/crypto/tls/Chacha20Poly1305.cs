using org.bouncycastle.crypto.engines;
using org.bouncycastle.crypto.macs;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.tls
{

						
	/// <summary>
	/// draft-ietf-tls-chacha20-poly1305-04
	/// </summary>
	public class Chacha20Poly1305 : TlsCipher
	{
		private static readonly byte[] ZEROES = new byte[15];

		protected internal TlsContext context;

		protected internal ChaCha7539Engine encryptCipher, decryptCipher;
		protected internal byte[] encryptIV, decryptIV;

		public Chacha20Poly1305(TlsContext context)
		{
			if (!TlsUtils.isTLSv12(context))
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			this.context = context;

			int cipherKeySize = 32;
			// TODO SecurityParameters.fixed_iv_length
			int fixed_iv_length = 12;
			// TODO SecurityParameters.record_iv_length = 0

			int key_block_size = (2 * cipherKeySize) + (2 * fixed_iv_length);

			byte[] key_block = TlsUtils.calculateKeyBlock(context, key_block_size);

			int offset = 0;

			KeyParameter client_write_key = new KeyParameter(key_block, offset, cipherKeySize);
			offset += cipherKeySize;
			KeyParameter server_write_key = new KeyParameter(key_block, offset, cipherKeySize);
			offset += cipherKeySize;
			byte[] client_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
			offset += fixed_iv_length;
			byte[] server_write_IV = Arrays.copyOfRange(key_block, offset, offset + fixed_iv_length);
			offset += fixed_iv_length;

			if (offset != key_block_size)
			{
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}

			this.encryptCipher = new ChaCha7539Engine();
			this.decryptCipher = new ChaCha7539Engine();

			KeyParameter encryptKey, decryptKey;
			if (context.isServer())
			{
				encryptKey = server_write_key;
				decryptKey = client_write_key;
				this.encryptIV = server_write_IV;
				this.decryptIV = client_write_IV;
			}
			else
			{
				encryptKey = client_write_key;
				decryptKey = server_write_key;
				this.encryptIV = client_write_IV;
				this.decryptIV = server_write_IV;
			}

			this.encryptCipher.init(true, new ParametersWithIV(encryptKey, encryptIV));
			this.decryptCipher.init(false, new ParametersWithIV(decryptKey, decryptIV));
		}

		public virtual int getPlaintextLimit(int ciphertextLimit)
		{
			return ciphertextLimit - 16;
		}

		public virtual byte[] encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)
		{
			KeyParameter macKey = initRecord(encryptCipher, true, seqNo, encryptIV);

			byte[] output = new byte[len + 16];
			encryptCipher.processBytes(plaintext, offset, len, output, 0);

			byte[] additionalData = getAdditionalData(seqNo, type, len);
			byte[] mac = calculateRecordMAC(macKey, additionalData, output, 0, len);
			JavaSystem.arraycopy(mac, 0, output, len, mac.Length);

			return output;
		}

		public virtual byte[] decodeCiphertext(long seqNo, short type, byte[] ciphertext, int offset, int len)
		{
			if (getPlaintextLimit(len) < 0)
			{
				throw new TlsFatalAlert(AlertDescription.decode_error);
			}

			KeyParameter macKey = initRecord(decryptCipher, false, seqNo, decryptIV);

			int plaintextLength = len - 16;

			byte[] additionalData = getAdditionalData(seqNo, type, plaintextLength);
			byte[] calculatedMAC = calculateRecordMAC(macKey, additionalData, ciphertext, offset, plaintextLength);
			byte[] receivedMAC = Arrays.copyOfRange(ciphertext, offset + plaintextLength, offset + len);

			if (!Arrays.constantTimeAreEqual(calculatedMAC, receivedMAC))
			{
				throw new TlsFatalAlert(AlertDescription.bad_record_mac);
			}

			byte[] output = new byte[plaintextLength];
			decryptCipher.processBytes(ciphertext, offset, plaintextLength, output, 0);
			return output;
		}

		public virtual KeyParameter initRecord(StreamCipher cipher, bool forEncryption, long seqNo, byte[] iv)
		{
			byte[] nonce = calculateNonce(seqNo, iv);
			cipher.init(forEncryption, new ParametersWithIV(null, nonce));
			return generateRecordMACKey(cipher);
		}

		public virtual byte[] calculateNonce(long seqNo, byte[] iv)
		{
			byte[] nonce = new byte[12];
			TlsUtils.writeUint64(seqNo, nonce, 4);

			for (int i = 0; i < 12; ++i)
			{
				nonce[i] ^= iv[i];
			}

			return nonce;
		}

		public virtual KeyParameter generateRecordMACKey(StreamCipher cipher)
		{
			byte[] firstBlock = new byte[64];
			cipher.processBytes(firstBlock, 0, firstBlock.Length, firstBlock, 0);

			KeyParameter macKey = new KeyParameter(firstBlock, 0, 32);
			Arrays.fill(firstBlock, 0);
			return macKey;
		}

		public virtual byte[] calculateRecordMAC(KeyParameter macKey, byte[] additionalData, byte[] buf, int off, int len)
		{
			Mac mac = new Poly1305();
			mac.init(macKey);

			updateRecordMACText(mac, additionalData, 0, additionalData.Length);
			updateRecordMACText(mac, buf, off, len);
			updateRecordMACLength(mac, additionalData.Length);
			updateRecordMACLength(mac, len);

			byte[] output = new byte[mac.getMacSize()];
			mac.doFinal(output, 0);
			return output;
		}

		public virtual void updateRecordMACLength(Mac mac, int len)
		{
			byte[] longLen = Pack.longToLittleEndian(len & 0xFFFFFFFFL);
			mac.update(longLen, 0, longLen.Length);
		}

		public virtual void updateRecordMACText(Mac mac, byte[] buf, int off, int len)
		{
			mac.update(buf, off, len);

			int partial = len % 16;
			if (partial != 0)
			{
				mac.update(ZEROES, 0, 16 - partial);
			}
		}

		public virtual byte[] getAdditionalData(long seqNo, short type, int len)
		{
			/*
			 * additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
			 * TLSCompressed.length
			 */
			byte[] additional_data = new byte[13];
			TlsUtils.writeUint64(seqNo, additional_data, 0);
			TlsUtils.writeUint8(type, additional_data, 8);
			TlsUtils.writeVersion(context.getServerVersion(), additional_data, 9);
			TlsUtils.writeUint16(len, additional_data, 11);

			return additional_data;
		}
	}

}