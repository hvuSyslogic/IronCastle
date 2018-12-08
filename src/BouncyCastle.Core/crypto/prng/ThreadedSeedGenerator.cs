using System.Threading;

namespace org.bouncycastle.crypto.prng
{
	/// <summary>
	/// A thread based seed generator - one source of randomness.
	/// <para>
	/// Based on an idea from Marcus Lippert.
	/// </para>
	/// </summary>
	public class ThreadedSeedGenerator
	{
		public class SeedGenerator : Runnable
		{
			private readonly ThreadedSeedGenerator outerInstance;

			public SeedGenerator(ThreadedSeedGenerator outerInstance)
			{
				this.outerInstance = outerInstance;
			}

			internal volatile int counter = 0;
			internal volatile bool stop = false;

			public virtual void run()
			{
				while (!this.stop)
				{
					this.counter++;
				}

			}

			public virtual byte[] generateSeed(int numbytes, bool fast)
			{
				Thread t = new Thread(this);
				byte[] result = new byte[numbytes];
				this.counter = 0;
				this.stop = false;
				int last = 0;
				int end;

				t.start();
				if (fast)
				{
					end = numbytes;
				}
				else
				{
					end = numbytes * 8;
				}
				for (int i = 0; i < end; i++)
				{
					while (this.counter == last)
					{
						try
						{
							Thread.sleep(1);
						}
						catch (InterruptedException)
						{
							// ignore
						}
					}
					last = this.counter;
					if (fast)
					{
						result[i] = unchecked((byte)(last & 0xff));
					}
					else
					{
						int bytepos = i / 8;
						result[bytepos] = (byte)((result[bytepos] << 1) | (last & 1));
					}

				}
				stop = true;
				return result;
			}
		}

		/// <summary>
		/// Generate seed bytes. Set fast to false for best quality.
		/// <para>
		/// If fast is set to true, the code should be round about 8 times faster when
		/// generating a long sequence of random bytes. 20 bytes of random values using
		/// the fast mode take less than half a second on a Nokia e70. If fast is set to false,
		/// it takes round about 2500 ms.
		/// </para> </summary>
		/// <param name="numBytes"> the number of bytes to generate </param>
		/// <param name="fast"> true if fast mode should be used </param>
		public virtual byte[] generateSeed(int numBytes, bool fast)
		{
			SeedGenerator gen = new SeedGenerator(this);

			return gen.generateSeed(numBytes, fast);
		}
	}

}