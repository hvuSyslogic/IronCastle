using System;

namespace org.bouncycastle.jce.provider.test
{


	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;
	using TestFailedException = org.bouncycastle.util.test.TestFailedException;

	public abstract class BaseBlockCipherTest : SimpleTest
	{
		internal string algorithm;

		public BaseBlockCipherTest(string algorithm)
		{
			this.algorithm = algorithm;
		}

		public override string getName()
		{
			return algorithm;
		}

		public virtual void oidTest(string[] oids, string[] names, int groupSize)
		{
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
			IvParameterSpec ivSpec = new IvParameterSpec(new byte[16]);

			for (int i = 0; i != oids.Length; i++)
			{
				Cipher c1 = Cipher.getInstance(oids[i], "BC");
				Cipher c2 = Cipher.getInstance(names[i], "BC");
				KeyGenerator kg = KeyGenerator.getInstance(oids[i], "BC");

				SecretKey k = kg.generateKey();

				if (names[i].IndexOf("/ECB/", StringComparison.Ordinal) > 0)
				{
					c1.init(Cipher.ENCRYPT_MODE, k);
					c2.init(Cipher.DECRYPT_MODE, k);
				}
				else
				{
					c1.init(Cipher.ENCRYPT_MODE, k, ivSpec);
					c2.init(Cipher.DECRYPT_MODE, k, ivSpec);
				}

				byte[] result = c2.doFinal(c1.doFinal(data));

				if (!areEqual(data, result))
				{
					fail("failed OID test");
				}

				if (k.getEncoded().length != (16 + ((i / groupSize) * 8)))
				{
					fail("failed key length test");
				}
			}
		}

		public virtual void wrapOidTest(string[] oids, string name)
		{
			byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

			for (int i = 0; i != oids.Length; i++)
			{
				Cipher c1 = Cipher.getInstance(oids[i], "BC");
				Cipher c2 = Cipher.getInstance(name, "BC");
				KeyGenerator kg = KeyGenerator.getInstance(oids[i], "BC");

				SecretKey k = kg.generateKey();

				c1.init(Cipher.WRAP_MODE, k);
				c2.init(Cipher.UNWRAP_MODE, k);

				Key wKey = c2.unwrap(c1.wrap(new SecretKeySpec(data, algorithm)), algorithm, Cipher.SECRET_KEY);

				if (!areEqual(data, wKey.getEncoded()))
				{
					fail("failed wrap OID test");
				}

				if (k.getEncoded().length != (16 + (i * 8)))
				{
					fail("failed key length test");
				}
			}
		}

		public virtual void wrapTest(int id, string wrappingAlgorithm, byte[] kek, byte[] @in, byte[] @out)
		{
			wrapTest(id, wrappingAlgorithm, kek, null, null, @in, @out);
		}

		public virtual void wrapTest(int id, string wrappingAlgorithm, byte[] kek, byte[] iv, SecureRandom rand, byte[] @in, byte[] @out)
		{
			Cipher wrapper = Cipher.getInstance(wrappingAlgorithm, "BC");

			if (iv != null)
			{
				wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, algorithm), new IvParameterSpec(iv), rand);
			}
			else
			{
				wrapper.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, algorithm), rand);
			}

			try
			{
				byte[] cText = wrapper.wrap(new SecretKeySpec(@in, algorithm));
				if (!areEqual(cText, @out))
				{
					fail("failed wrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@out)) + " got " + StringHelper.NewString(Hex.encode(cText)));
				}
			}
			catch (TestFailedException e)
			{
				throw e;
			}
			catch (Exception e)
			{
				fail("failed wrap test exception " + e.ToString(), e);
			}

			if (iv != null)
			{
				wrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, algorithm), new IvParameterSpec(iv));
			}
			else
			{
				wrapper.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, algorithm));
			}

			try
			{
				Key pText = wrapper.unwrap(@out, algorithm, Cipher.SECRET_KEY);
				if (!areEqual(pText.getEncoded(), @in))
				{
					fail("failed unwrap test " + id + " expected " + StringHelper.NewString(Hex.encode(@in)) + " got " + StringHelper.NewString(Hex.encode(pText.getEncoded())));
				}
			}
			catch (Exception e)
			{
				fail("failed unwrap test exception " + e.ToString(), e);
			}
		}
	}

}