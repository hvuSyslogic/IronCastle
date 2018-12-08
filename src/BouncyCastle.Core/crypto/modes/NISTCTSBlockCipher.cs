/// <summary>
/// A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
/// be used to produce cipher text which is the same length as the plain text.
/// </summary>

using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{

	/// <summary>
	/// A Cipher Text Stealing (CTS) mode cipher. CTS allows block ciphers to
	/// be used to produce cipher text which is the same length as the plain text.
	/// <para>
	///     This class implements the NIST version as documented in "Addendum to NIST SP 800-38A, Recommendation for Block Cipher Modes of Operation: Three Variants of Ciphertext Stealing for CBC Mode"
	/// </para>
	/// </summary>
	public class NISTCTSBlockCipher : BufferedBlockCipher
	{
		public const int CS1 = 1;
		public const int CS2 = 2;
		public const int CS3 = 3;

		private readonly int type;
		private readonly int blockSize;

		/// <summary>
		/// Create a buffered block cipher that uses NIST Cipher Text Stealing
		/// </summary>
		/// <param name="type"> type of CTS mode (CS1, CS2, or CS3) </param>
		/// <param name="cipher"> the underlying block cipher used to create the CBC block cipher this cipher uses.. </param>
		public NISTCTSBlockCipher(int type, BlockCipher cipher)
		{
			this.type = type;
			this.cipher = new CBCBlockCipher(cipher);

			blockSize = cipher.getBlockSize();

			buf = new byte[blockSize * 2];
			bufOff = 0;
		}

		/// <summary>
		/// return the size of the output buffer required for an update
		/// an input of len bytes.
		/// </summary>
		/// <param name="len"> the length of the input. </param>
		/// <returns> the space required to accommodate a call to update
		/// with len bytes of input. </returns>
		public override int getUpdateOutputSize(int len)
		{
			int total = len + bufOff;
			int leftOver = total % buf.Length;

			if (leftOver == 0)
			{
				return total - buf.Length;
			}

			return total - leftOver;
		}

		/// <summary>
		/// return the size of the output buffer required for an update plus a
		/// doFinal with an input of len bytes.
		/// </summary>
		/// <param name="len"> the length of the input. </param>
		/// <returns> the space required to accommodate a call to update and doFinal
		/// with len bytes of input. </returns>
		public override int getOutputSize(int len)
		{
			return len + bufOff;
		}

		/// <summary>
		/// process a single byte, producing an output block if necessary.
		/// </summary>
		/// <param name="in"> the input byte. </param>
		/// <param name="out"> the space for any output that might be produced. </param>
		/// <param name="outOff"> the offset from which the output will be copied. </param>
		/// <returns> the number of output bytes copied to out. </returns>
		/// <exception cref="org.bouncycastle.crypto.DataLengthException"> if there isn't enough space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		public override int processByte(byte @in, byte[] @out, int outOff)
		{
			int resultLen = 0;

			if (bufOff == buf.Length)
			{
				resultLen = cipher.processBlock(buf, 0, @out, outOff);
				JavaSystem.arraycopy(buf, blockSize, buf, 0, blockSize);

				bufOff = blockSize;
			}

			buf[bufOff++] = @in;

			return resultLen;
		}

		/// <summary>
		/// process an array of bytes, producing output if necessary.
		/// </summary>
		/// <param name="in"> the input byte array. </param>
		/// <param name="inOff"> the offset at which the input data starts. </param>
		/// <param name="len"> the number of bytes to be copied out of the input array. </param>
		/// <param name="out"> the space for any output that might be produced. </param>
		/// <param name="outOff"> the offset from which the output will be copied. </param>
		/// <returns> the number of output bytes copied to out. </returns>
		/// <exception cref="org.bouncycastle.crypto.DataLengthException"> if there isn't enough space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		public override int processBytes(byte[] @in, int inOff, int len, byte[] @out, int outOff)
		{
			if (len < 0)
			{
				throw new IllegalArgumentException("Can't have a negative input length!");
			}

			int blockSize = getBlockSize();
			int length = getUpdateOutputSize(len);

			if (length > 0)
			{
				if ((outOff + length) > @out.Length)
				{
					throw new OutputLengthException("output buffer too short");
				}
			}

			int resultLen = 0;
			int gapLen = buf.Length - bufOff;

			if (len > gapLen)
			{
				JavaSystem.arraycopy(@in, inOff, buf, bufOff, gapLen);

				resultLen += cipher.processBlock(buf, 0, @out, outOff);
				JavaSystem.arraycopy(buf, blockSize, buf, 0, blockSize);

				bufOff = blockSize;

				len -= gapLen;
				inOff += gapLen;

				while (len > blockSize)
				{
					JavaSystem.arraycopy(@in, inOff, buf, bufOff, blockSize);
					resultLen += cipher.processBlock(buf, 0, @out, outOff + resultLen);
					JavaSystem.arraycopy(buf, blockSize, buf, 0, blockSize);

					len -= blockSize;
					inOff += blockSize;
				}
			}

			JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

			bufOff += len;

			return resultLen;
		}

		/// <summary>
		/// Process the last block in the buffer.
		/// </summary>
		/// <param name="out"> the array the block currently being held is copied into. </param>
		/// <param name="outOff"> the offset at which the copying starts. </param>
		/// <returns> the number of output bytes copied to out. </returns>
		/// <exception cref="org.bouncycastle.crypto.DataLengthException"> if there is insufficient space in out for
		/// the output. </exception>
		/// <exception cref="IllegalStateException"> if the underlying cipher is not
		/// initialised. </exception>
		/// <exception cref="org.bouncycastle.crypto.InvalidCipherTextException"> if cipher text decrypts wrongly (in
		/// case the exception will never get thrown). </exception>
		public override int doFinal(byte[] @out, int outOff)
		{
			if (bufOff + outOff > @out.Length)
			{
				throw new OutputLengthException("output buffer to small in doFinal");
			}

			int blockSize = cipher.getBlockSize();
			int len = bufOff - blockSize;
			byte[] block = new byte[blockSize];

			if (forEncryption)
			{
				if (bufOff < blockSize)
				{
					throw new DataLengthException("need at least one block of input for NISTCTS");
				}

				if (bufOff > blockSize)
				{
					byte[] lastBlock = new byte[blockSize];

					if (this.type == CS2 || this.type == CS3)
					{
						cipher.processBlock(buf, 0, block, 0);

						JavaSystem.arraycopy(buf, blockSize, lastBlock, 0, len);

						cipher.processBlock(lastBlock, 0, lastBlock, 0);

						if (this.type == CS2 && len == blockSize)
						{
							JavaSystem.arraycopy(block, 0, @out, outOff, blockSize);

							JavaSystem.arraycopy(lastBlock, 0, @out, outOff + blockSize, len);
						}
						else
						{
							JavaSystem.arraycopy(lastBlock, 0, @out, outOff, blockSize);

							JavaSystem.arraycopy(block, 0, @out, outOff + blockSize, len);
						}
					}
					else
					{
						JavaSystem.arraycopy(buf, 0, block, 0, blockSize);
						cipher.processBlock(block, 0, block, 0);
						JavaSystem.arraycopy(block, 0, @out, outOff, len);

						JavaSystem.arraycopy(buf, bufOff - len, lastBlock, 0, len);
						cipher.processBlock(lastBlock, 0, lastBlock, 0);
						JavaSystem.arraycopy(lastBlock, 0, @out, outOff + len, blockSize);
					}
				}
				else
				{
					cipher.processBlock(buf, 0, block, 0);

					JavaSystem.arraycopy(block, 0, @out, outOff, blockSize);
				}
			}
			else
			{
				if (bufOff < blockSize)
				{
					throw new DataLengthException("need at least one block of input for CTS");
				}

				byte[] lastBlock = new byte[blockSize];

				if (bufOff > blockSize)
				{
					if (this.type == CS3 || (this.type == CS2 && ((buf.Length - bufOff) % blockSize) != 0))
					{
						if (cipher is CBCBlockCipher)
						{
							BlockCipher c = ((CBCBlockCipher)cipher).getUnderlyingCipher();

							c.processBlock(buf, 0, block, 0);
						}
						else
						{
							cipher.processBlock(buf, 0, block, 0);
						}

						for (int i = blockSize; i != bufOff; i++)
						{
							lastBlock[i - blockSize] = (byte)(block[i - blockSize] ^ buf[i]);
						}

						JavaSystem.arraycopy(buf, blockSize, block, 0, len);

						cipher.processBlock(block, 0, @out, outOff);
						JavaSystem.arraycopy(lastBlock, 0, @out, outOff + blockSize, len);
					}
					else
					{
						BlockCipher c = ((CBCBlockCipher)cipher).getUnderlyingCipher();

						c.processBlock(buf, bufOff - blockSize, lastBlock, 0);

						JavaSystem.arraycopy(buf, 0, block, 0, blockSize);

						if (len != blockSize)
						{
							JavaSystem.arraycopy(lastBlock, len, block, len, blockSize - len);
						}

						cipher.processBlock(block, 0, block, 0);

						JavaSystem.arraycopy(block, 0, @out, outOff, blockSize);

						for (int i = 0; i != len; i++)
						{
							lastBlock[i] ^= buf[i];
						}

						JavaSystem.arraycopy(lastBlock, 0, @out, outOff + blockSize, len);
					}
				}
				else
				{
					cipher.processBlock(buf, 0, block, 0);

					JavaSystem.arraycopy(block, 0, @out, outOff, blockSize);
				}
			}

			int offset = bufOff;

			reset();

			return offset;
		}
	}

}