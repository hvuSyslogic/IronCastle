﻿using org.bouncycastle.util;

namespace org.bouncycastle.crypto.@params
{
	
	/// <summary>
	/// Parameters for tweakable block ciphers.
	/// </summary>
	public class TweakableBlockCipherParameters : CipherParameters
	{
		private readonly byte[] tweak;
		private readonly KeyParameter key;


		public TweakableBlockCipherParameters(KeyParameter key, byte[] tweak)
		{
			this.key = key;
			this.tweak = Arrays.clone(tweak);
		}

		/// <summary>
		/// Gets the key.
		/// </summary>
		/// <returns> the key to use, or <code>null</code> to use the current key. </returns>
		public virtual KeyParameter getKey()
		{
			return key;
		}

		/// <summary>
		/// Gets the tweak value.
		/// </summary>
		/// <returns> the tweak to use, or <code>null</code> to use the current tweak. </returns>
		public virtual byte[] getTweak()
		{
			return tweak;
		}
	}

}