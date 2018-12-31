using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.engines
{

			
	/// <summary>
	/// Implementation of DSTU7624 KEY WRAP mode
	/// </summary>
	public class DSTU7624WrapEngine : Wrapper
	{

		private const int BYTES_IN_INTEGER = 4;

		private bool forWrapping;
		private DSTU7624Engine engine;

		private byte[] B, intArray;
		private byte[] checkSumArray, zeroArray;
		private ArrayList<byte[]> Btemp;


		public DSTU7624WrapEngine(int blockBitLength)
		{

			this.engine = new DSTU7624Engine(blockBitLength);
			this.B = new byte[engine.getBlockSize() / 2];
			this.checkSumArray = new byte[engine.getBlockSize()];
			this.zeroArray = new byte[engine.getBlockSize()];
			this.Btemp = new ArrayList<byte[]>();
			this.intArray = new byte[BYTES_IN_INTEGER];

		}

		public virtual void init(bool forWrapping, CipherParameters param)
		{
			if (param is ParametersWithRandom)
			{
				param = ((ParametersWithRandom)param).getParameters();
			}

			this.forWrapping = forWrapping;
			if (param is KeyParameter)
			{
				engine.init(forWrapping, param);
			}
			else
			{
				throw new IllegalArgumentException("invalid parameters passed to DSTU7624WrapEngine");
			}

		}

		public virtual string getAlgorithmName()
		{
			return "DSTU7624WrapEngine";
		}

		public virtual byte[] wrap(byte[] @in, int inOff, int inLen)
		{
			if (!forWrapping)
			{
				throw new IllegalStateException("not set for wrapping");
			}

			if ((inLen % engine.getBlockSize()) != 0)
			{
				//Partial blocks not supported
				throw new DataLengthException("wrap data must be a multiple of " + engine.getBlockSize() + " bytes");
			}

			if (inOff + inLen > @in.Length)
			{
				throw new DataLengthException("input buffer too short");
			}

			int n = 2 * (1 + inLen / engine.getBlockSize()); // Defined in DSTU7624 standard
			int V = (n - 1) * 6; // Defined in DSTU7624 standard


			byte[] wrappedBuffer = new byte[inLen + engine.getBlockSize()];
			JavaSystem.arraycopy(@in, inOff, wrappedBuffer, 0, inLen);

			JavaSystem.arraycopy(wrappedBuffer, 0, B, 0, engine.getBlockSize() / 2);

			Btemp.clear();

			int bHalfBlocksLen = wrappedBuffer.Length - engine.getBlockSize() / 2;
			int bufOff = engine.getBlockSize() / 2;
			while (bHalfBlocksLen != 0)
			{
				byte[] temp = new byte[engine.getBlockSize() / 2];
				JavaSystem.arraycopy(wrappedBuffer, bufOff, temp, 0, engine.getBlockSize() / 2);

				Btemp.add(temp);

				bHalfBlocksLen -= engine.getBlockSize() / 2;
				bufOff += engine.getBlockSize() / 2;
			}

			for (int j = 0; j < V; j++)
			{
				JavaSystem.arraycopy(B, 0, wrappedBuffer, 0, engine.getBlockSize() / 2);
				JavaSystem.arraycopy(Btemp.get(0), 0, wrappedBuffer, engine.getBlockSize() / 2, engine.getBlockSize() / 2);

				engine.processBlock(wrappedBuffer, 0, wrappedBuffer, 0);

				intToBytes(j + 1, intArray, 0);
				for (int byteNum = 0; byteNum < BYTES_IN_INTEGER; byteNum++)
				{
					wrappedBuffer[byteNum + engine.getBlockSize() / 2] ^= intArray[byteNum];
				}

				JavaSystem.arraycopy(wrappedBuffer, engine.getBlockSize() / 2, B, 0, engine.getBlockSize() / 2);

				for (int i = 2; i < n; i++)
				{
					JavaSystem.arraycopy(Btemp.get(i - 1), 0, Btemp.get(i - 2), 0, engine.getBlockSize() / 2);
				}

				JavaSystem.arraycopy(wrappedBuffer, 0, Btemp.get(n - 2), 0, engine.getBlockSize() / 2);
			}


			JavaSystem.arraycopy(B, 0, wrappedBuffer, 0, engine.getBlockSize() / 2);
			bufOff = engine.getBlockSize() / 2;

			for (int i = 0; i < n - 1; i++)
			{
				JavaSystem.arraycopy(Btemp.get(i), 0, wrappedBuffer, bufOff, engine.getBlockSize() / 2);
				bufOff += engine.getBlockSize() / 2;
			}

			return wrappedBuffer;

		}

		public virtual byte[] unwrap(byte[] @in, int inOff, int inLen)
		{
			if (forWrapping)
			{
				throw new IllegalStateException("not set for unwrapping");
			}

			if ((inLen % engine.getBlockSize()) != 0)
			{
				//Partial blocks not supported
				throw new DataLengthException("unwrap data must be a multiple of " + engine.getBlockSize() + " bytes");
			}

			int n = 2 * inLen / engine.getBlockSize();

			int V = (n - 1) * 6;

			byte[] buffer = new byte[inLen];
			JavaSystem.arraycopy(@in, inOff, buffer, 0, inLen);

			byte[] B = new byte[engine.getBlockSize() / 2];
			JavaSystem.arraycopy(buffer, 0, B, 0, engine.getBlockSize() / 2);

			Btemp.clear();

			int bHalfBlocksLen = buffer.Length - engine.getBlockSize() / 2;
			int bufOff = engine.getBlockSize() / 2;
			while (bHalfBlocksLen != 0)
			{
				byte[] temp = new byte[engine.getBlockSize() / 2];
				JavaSystem.arraycopy(buffer, bufOff, temp, 0, engine.getBlockSize() / 2);

				Btemp.add(temp);

				bHalfBlocksLen -= engine.getBlockSize() / 2;
				bufOff += engine.getBlockSize() / 2;
			}

			for (int j = 0; j < V; j++)
			{
				JavaSystem.arraycopy(Btemp.get(n - 2), 0, buffer, 0, engine.getBlockSize() / 2);
				JavaSystem.arraycopy(B, 0, buffer, engine.getBlockSize() / 2, engine.getBlockSize() / 2);
				intToBytes(V - j, intArray, 0);
				for (int byteNum = 0; byteNum < BYTES_IN_INTEGER; byteNum++)
				{
					buffer[byteNum + engine.getBlockSize() / 2] ^= intArray[byteNum];
				}

				engine.processBlock(buffer, 0, buffer, 0);

				JavaSystem.arraycopy(buffer, 0, B, 0, engine.getBlockSize() / 2);

				for (int i = 2; i < n; i++)
				{
					JavaSystem.arraycopy(Btemp.get(n - i - 1), 0, Btemp.get(n - i), 0, engine.getBlockSize() / 2);
				}

				JavaSystem.arraycopy(buffer, engine.getBlockSize() / 2, Btemp.get(0), 0, engine.getBlockSize() / 2);
			}

			JavaSystem.arraycopy(B, 0, buffer, 0, engine.getBlockSize() / 2);
			bufOff = engine.getBlockSize() / 2;

			for (int i = 0; i < n - 1; i++)
			{
				JavaSystem.arraycopy(Btemp.get(i), 0, buffer, bufOff, engine.getBlockSize() / 2);
				bufOff += engine.getBlockSize() / 2;
			}

			JavaSystem.arraycopy(buffer, buffer.Length - engine.getBlockSize(), checkSumArray, 0, engine.getBlockSize());

			byte[] wrappedBuffer = new byte[buffer.Length - engine.getBlockSize()];
			if (!Arrays.areEqual(checkSumArray, zeroArray))
			{
				throw new InvalidCipherTextException("checksum failed");
			}
			else
			{
				JavaSystem.arraycopy(buffer, 0, wrappedBuffer, 0, buffer.Length - engine.getBlockSize());
			}


			return wrappedBuffer;
		}


		private void intToBytes(int number, byte[] outBytes, int outOff)
		{
			outBytes[outOff + 3] = (byte)(number >> 24);
			outBytes[outOff + 2] = (byte)(number >> 16);
			outBytes[outOff + 1] = (byte)(number >> 8);
			outBytes[outOff] = (byte)number;
		}
	}

}