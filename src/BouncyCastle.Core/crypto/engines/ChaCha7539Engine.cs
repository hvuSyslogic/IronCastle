using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.engines
{
	using Pack = org.bouncycastle.util.Pack;

	/// <summary>
	/// Implementation of Daniel J. Bernstein's ChaCha stream cipher.
	/// </summary>
	public class ChaCha7539Engine : Salsa20Engine
	{
		/// <summary>
		/// Creates a 20 rounds ChaCha engine.
		/// </summary>
		public ChaCha7539Engine() : base()
		{
		}

		public override string getAlgorithmName()
		{
			return "ChaCha7539-" + rounds;
		}

		public override int getNonceSize()
		{
			return 12;
		}

		public override void advanceCounter(long diff)
		{
			int hi = (int)((long)((ulong)diff >> 32));
			int lo = (int)diff;

			if (hi > 0)
			{
				throw new IllegalStateException("attempt to increase counter past 2^32.");
			}

			int oldState = engineState[12];

			engineState[12] += lo;

			if (oldState != 0 && engineState[12] < oldState)
			{
				throw new IllegalStateException("attempt to increase counter past 2^32.");
			}
		}

		public override void advanceCounter()
		{
			if (++engineState[12] == 0)
			{
				throw new IllegalStateException("attempt to increase counter past 2^32.");
			}
		}

		public override void retreatCounter(long diff)
		{
			int hi = (int)((long)((ulong)diff >> 32));
			int lo = (int)diff;

			if (hi != 0)
			{
				throw new IllegalStateException("attempt to reduce counter past zero.");
			}

			if ((engineState[12] & 0xffffffffL) >= (lo & 0xffffffffL))
			{
				engineState[12] -= lo;
			}
			else
			{
				throw new IllegalStateException("attempt to reduce counter past zero.");
			}
		}

		public override void retreatCounter()
		{
			if (engineState[12] == 0)
			{
				throw new IllegalStateException("attempt to reduce counter past zero.");
			}

			--engineState[12];
		}

		public override long getCounter()
		{
			return engineState[12] & 0xffffffffL;
		}

		public override void resetCounter()
		{
			engineState[12] = 0;
		}

		public override void setKey(byte[] keyBytes, byte[] ivBytes)
		{
			if (keyBytes != null)
			{
				if (keyBytes.Length != 32)
				{
					throw new IllegalArgumentException(getAlgorithmName() + " requires 256 bit key");
				}

				packTauOrSigma(keyBytes.Length, engineState, 0);

				// Key
				Pack.littleEndianToInt(keyBytes, 0, engineState, 4, 8);
			}

			// IV
			Pack.littleEndianToInt(ivBytes, 0, engineState, 13, 3);
		}

		public override void generateKeyStream(byte[] output)
		{
			ChaChaEngine.chachaCore(rounds, engineState, x);
			Pack.intToLittleEndian(x, output, 0);
		}
	}

}