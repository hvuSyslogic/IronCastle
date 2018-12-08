using System;

namespace org.bouncycastle.pqc.jcajce.provider.test
{

	using TestCase = junit.framework.TestCase;

	public abstract class FlexiTest : TestCase
	{

		/// <summary>
		/// Source of randomness
		/// </summary>
		protected internal Random rand;

		/// <summary>
		/// Secure source of randomness
		/// </summary>
		protected internal SecureRandom sr;

		public virtual void setUp()
		{
			Security.addProvider(new BouncyCastlePQCProvider());
			// initialize sources of randomness
			rand = new Random();
			sr = new SecureRandom();
			// TODO need it?
			sr.setSeed(sr.generateSeed(20));
		}

		protected internal static void assertEquals(byte[] expected, byte[] actual)
		{
			assertTrue(Arrays.Equals(expected, actual));
		}

		protected internal static void assertEquals(string message, byte[] expected, byte[] actual)
		{
			assertTrue(message, Arrays.Equals(expected, actual));
		}

		protected internal static void assertEquals(int[] expected, int[] actual)
		{
			assertTrue(Arrays.Equals(expected, actual));
		}

		protected internal static void assertEquals(string message, int[] expected, int[] actual)
		{
			assertTrue(message, Arrays.Equals(expected, actual));
		}

		/// <summary>
		/// Method used to report test failure when in exception is thrown.
		/// </summary>
		/// <param name="e"> the exception </param>
		protected internal static void fail(Exception e)
		{
			fail("Exception thrown: " + e.GetType().getName() + ":\n" + e.Message);
		}

	}

}