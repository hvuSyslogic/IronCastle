using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.crypto.@params
{
	public class DESParameters : KeyParameter
	{
		public DESParameters(byte[] key) : base(key)
		{

			if (isWeakKey(key, 0))
			{
				throw new IllegalArgumentException("attempt to create weak DES key");
			}
		}

		/*
		 * DES Key length in bytes.
		 */
		public const int DES_KEY_LENGTH = 8;

		/*
		 * Table of weak and semi-weak keys taken from Schneier pp281
		 */
		private const int N_DES_WEAK_KEYS = 16;

		private static byte[] DES_weak_keys = new byte[] {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e, unchecked(0xe0), unchecked(0xe0), unchecked(0xe0), unchecked(0xe0), unchecked(0xf1), unchecked(0xf1), unchecked(0xf1), unchecked(0xf1), unchecked(0xfe), unchecked(0xfe), unchecked(0xfe), unchecked(0xfe), unchecked(0xfe), unchecked(0xfe), unchecked(0xfe), unchecked(0xfe), 0x01, unchecked(0xfe), 0x01, unchecked(0xfe), 0x01, unchecked(0xfe), 0x01, unchecked(0xfe), 0x1f, unchecked(0xe0), 0x1f, unchecked(0xe0), 0x0e, unchecked(0xf1), 0x0e, unchecked(0xf1), 0x01, unchecked(0xe0), 0x01, unchecked(0xe0), 0x01, unchecked(0xf1), 0x01, unchecked(0xf1), 0x1f, unchecked(0xfe), 0x1f, unchecked(0xfe), 0x0e, unchecked(0xfe), 0x0e, unchecked(0xfe), 0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, unchecked(0xe0), unchecked(0xfe), unchecked(0xe0), unchecked(0xfe), unchecked(0xf1), unchecked(0xfe), unchecked(0xf1), unchecked(0xfe), unchecked(0xfe), 0x01, unchecked(0xfe), 0x01, unchecked(0xfe), 0x01, unchecked(0xfe), 0x01, unchecked(0xe0), 0x1f, unchecked(0xe0), 0x1f, unchecked(0xf1), 0x0e, unchecked(0xf1), 0x0e, unchecked(0xe0), 0x01, unchecked(0xe0), 0x01, unchecked(0xf1), 0x01, unchecked(0xf1), 0x01, unchecked(0xfe), 0x1f, unchecked(0xfe), 0x1f, unchecked(0xfe), 0x0e, unchecked(0xfe), 0x0e, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01, unchecked(0xfe), unchecked(0xe0), unchecked(0xfe), unchecked(0xe0), unchecked(0xfe), unchecked(0xf1), unchecked(0xfe), unchecked(0xf1)};

		/// <summary>
		/// DES has 16 weak keys.  This method will check
		/// if the given DES key material is weak or semi-weak.
		/// Key material that is too short is regarded as weak.
		/// <para>
		/// See <a href="http://www.counterpane.com/applied.html">"Applied
		/// Cryptography"</a> by Bruce Schneier for more information.
		/// 
		/// </para>
		/// </summary>
		/// <returns> true if the given DES key material is weak or semi-weak,
		///     false otherwise. </returns>
		public static bool isWeakKey(byte[] key, int offset)
		{
			if (key.Length - offset < DES_KEY_LENGTH)
			{
				throw new IllegalArgumentException("key material too short.");
			}

			for (int i = 0; i < N_DES_WEAK_KEYS; i++)
			{
				for (int j = 0; j < DES_KEY_LENGTH; j++)
				{
					if (key[j + offset] != DES_weak_keys[i * DES_KEY_LENGTH + j])
					{
						goto nextkeyContinue;
					}
				}

				return true;
				nextkeyContinue:;
			}
			nextkeyBreak:
			return false;
		}

		/// <summary>
		/// DES Keys use the LSB as the odd parity bit.  This can
		/// be used to check for corrupt keys.
		/// </summary>
		/// <param name="bytes"> the byte array to set the parity on. </param>
		public static void setOddParity(byte[] bytes)
		{
			for (int i = 0; i < bytes.Length; i++)
			{
				int b = bytes[i];
				bytes[i] = unchecked((byte)((b & 0xfe) | ((((b >> 1) ^ (b >> 2) ^ (b >> 3) ^ (b >> 4) ^ (b >> 5) ^ (b >> 6) ^ (b >> 7)) ^ 0x01) & 0x01)));
			}
		}
	}

}