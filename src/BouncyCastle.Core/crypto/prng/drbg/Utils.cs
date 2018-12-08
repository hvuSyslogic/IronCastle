using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.prng.drbg
{

	using Integers = org.bouncycastle.util.Integers;

	public class Utils
	{
		internal static readonly Hashtable maxSecurityStrengths = new Hashtable();

		static Utils()
		{
			maxSecurityStrengths.put("SHA-1", Integers.valueOf(128));

			maxSecurityStrengths.put("SHA-224", Integers.valueOf(192));
			maxSecurityStrengths.put("SHA-256", Integers.valueOf(256));
			maxSecurityStrengths.put("SHA-384", Integers.valueOf(256));
			maxSecurityStrengths.put("SHA-512", Integers.valueOf(256));

			maxSecurityStrengths.put("SHA-512/224", Integers.valueOf(192));
			maxSecurityStrengths.put("SHA-512/256", Integers.valueOf(256));
		}

		internal static int getMaxSecurityStrength(Digest d)
		{
			return ((int?)maxSecurityStrengths.get(d.getAlgorithmName())).Value;
		}

		internal static int getMaxSecurityStrength(Mac m)
		{
			string name = m.getAlgorithmName();

			return ((int?)maxSecurityStrengths.get(name.Substring(0, name.IndexOf("/", StringComparison.Ordinal)))).Value;
		}

		/// <summary>
		/// Used by both Dual EC and Hash.
		/// </summary>
		internal static byte[] hash_df(Digest digest, byte[] seedMaterial, int seedLength)
		{
			 // 1. temp = the Null string.
			// 2. .
			// 3. counter = an 8-bit binary value representing the integer "1".
			// 4. For i = 1 to len do
			// Comment : In step 4.1, no_of_bits_to_return
			// is used as a 32-bit string.
			// 4.1 temp = temp || Hash (counter || no_of_bits_to_return ||
			// input_string).
			// 4.2 counter = counter + 1.
			// 5. requested_bits = Leftmost (no_of_bits_to_return) of temp.
			// 6. Return SUCCESS and requested_bits.
			byte[] temp = new byte[(seedLength + 7) / 8];

			int len = temp.Length / digest.getDigestSize();
			int counter = 1;

			byte[] dig = new byte[digest.getDigestSize()];

			for (int i = 0; i <= len; i++)
			{
				digest.update((byte)counter);

				digest.update((byte)(seedLength >> 24));
				digest.update((byte)(seedLength >> 16));
				digest.update((byte)(seedLength >> 8));
				digest.update((byte)seedLength);

				digest.update(seedMaterial, 0, seedMaterial.Length);

				digest.doFinal(dig, 0);

				int bytesToCopy = ((temp.Length - i * dig.Length) > dig.Length) ? dig.Length : (temp.Length - i * dig.Length);
				JavaSystem.arraycopy(dig, 0, temp, i * dig.Length, bytesToCopy);

				counter++;
			}

			// do a left shift to get rid of excess bits.
			if (seedLength % 8 != 0)
			{
				int shift = 8 - (seedLength % 8);
				int carry = 0;

				for (int i = 0; i != temp.Length; i++)
				{
					int b = temp[i] & 0xff;
					temp[i] = (byte)(((int)((uint)b >> shift)) | (carry << (8 - shift)));
					carry = b;
				}
			}

			return temp;
		}

		internal static bool isTooLarge(byte[] bytes, int maxBytes)
		{
			return bytes != null && bytes.Length > maxBytes;
		}
	}

}