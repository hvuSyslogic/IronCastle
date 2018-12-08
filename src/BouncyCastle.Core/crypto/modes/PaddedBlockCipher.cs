using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.modes
{

	/// <summary>
	/// A wrapper class that allows block ciphers to be used to process data in
	/// a piecemeal fashion with PKCS5/PKCS7 padding. The PaddedBlockCipher
	/// outputs a block only when the buffer is full and more data is being added,
	/// or on a doFinal (unless the current block in the buffer is a pad block).
	/// The padding mechanism used is the one outlined in PKCS5/PKCS7.
	/// </summary>
	/// @deprecated use org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher instead. 
	public class PaddedBlockCipher : BufferedBlockCipher
	{
		/// <summary>
		/// Create a buffered block cipher with, or without, padding.
		/// </summary>
		/// <param name="cipher"> the underlying block cipher this buffering object wraps. </param>
		public PaddedBlockCipher(BlockCipher cipher)
		{
			this.cipher = cipher;

			buf = new byte[cipher.getBlockSize()];
			bufOff = 0;
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
			int total = len + bufOff;
			int leftOver = total % buf.Length;

			if (leftOver == 0)
			{
				if (forEncryption)
				{
					return total + buf.Length;
				}

				return total;
			}

			return total - leftOver + buf.Length;
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
		/// process a single byte, producing an output block if neccessary.
		/// </summary>
		/// <param name="in"> the input byte. </param>
		/// <param name="out"> the space for any output that might be produced. </param>
		/// <param name="outOff"> the offset from which the output will be copied. </param>
		/// <exception cref="DataLengthException"> if there isn't enough space in out. </exception>
		/// <exception cref="IllegalStateException"> if the cipher isn't initialised. </exception>
		public override int processByte(byte @in, byte[] @out, int outOff)
		{
			int resultLen = 0;

			if (bufOff == buf.Length)
			{
				resultLen = cipher.processBlock(buf, 0, @out, outOff);
				bufOff = 0;
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
		/// <exception cref="DataLengthException"> if there isn't enough space in out. </exception>
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

				bufOff = 0;
				len -= gapLen;
				inOff += gapLen;

				while (len > buf.Length)
				{
					resultLen += cipher.processBlock(@in, inOff, @out, outOff + resultLen);

					len -= blockSize;
					inOff += blockSize;
				}
			}

			JavaSystem.arraycopy(@in, inOff, buf, bufOff, len);

			bufOff += len;

			return resultLen;
		}

		/// <summary>
		/// Process the last block in the buffer. If the buffer is currently
		/// full and padding needs to be added a call to doFinal will produce
		/// 2 * getBlockSize() bytes.
		/// </summary>
		/// <param name="out"> the array the block currently being held is copied into. </param>
		/// <param name="outOff"> the offset at which the copying starts. </param>
		/// <exception cref="DataLengthException"> if there is insufficient space in out for
		/// the output or we are decrypting and the input is not block size aligned. </exception>
		/// <exception cref="IllegalStateException"> if the underlying cipher is not
		/// initialised. </exception>
		/// <exception cref="InvalidCipherTextException"> if padding is expected and not found. </exception>
		public override int doFinal(byte[] @out, int outOff)
		{
			int blockSize = cipher.getBlockSize();
			int resultLen = 0;

			if (forEncryption)
			{
				if (bufOff == blockSize)
				{
					if ((outOff + 2 * blockSize) > @out.Length)
					{
						throw new OutputLengthException("output buffer too short");
					}

					resultLen = cipher.processBlock(buf, 0, @out, outOff);
					bufOff = 0;
				}

				//
				// add PKCS7 padding
				//
				byte code = (byte)(blockSize - bufOff);

				while (bufOff < blockSize)
				{
					buf[bufOff] = code;
					bufOff++;
				}

				resultLen += cipher.processBlock(buf, 0, @out, outOff + resultLen);
			}
			else
			{
				if (bufOff == blockSize)
				{
					resultLen = cipher.processBlock(buf, 0, buf, 0);
					bufOff = 0;
				}
				else
				{
					throw new DataLengthException("last block incomplete in decryption");
				}

				//
				// remove PKCS7 padding
				//
				int count = buf[blockSize - 1] & 0xff;

				if (count > blockSize)
				{
					throw new InvalidCipherTextException("pad block corrupted");
				}

				resultLen -= count;

				JavaSystem.arraycopy(buf, 0, @out, outOff, resultLen);
			}

			reset();

			return resultLen;
		}
	}

}