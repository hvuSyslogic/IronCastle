using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.prng.drbg
{
		
	/// <summary>
	/// A SP800-90A HMAC DRBG.
	/// </summary>
	public class HMacSP800DRBG : SP80090DRBG
	{
		private static readonly long RESEED_MAX = 1L << (48 - 1);
		private static readonly int MAX_BITS_REQUEST = 1 << (19 - 1);

		private byte[] _K;
		private byte[] _V;
		private long _reseedCounter;
		private EntropySource _entropySource;
		private Mac _hMac;
		private int _securityStrength;

		/// <summary>
		/// Construct a SP800-90A Hash DRBG.
		/// <para>
		/// Minimum entropy requirement is the security strength requested.
		/// </para> </summary>
		/// <param name="hMac"> Hash MAC to base the DRBG on. </param>
		/// <param name="securityStrength"> security strength required (in bits) </param>
		/// <param name="entropySource"> source of entropy to use for seeding/reseeding. </param>
		/// <param name="personalizationString"> personalization string to distinguish this DRBG (may be null). </param>
		/// <param name="nonce"> nonce to further distinguish this DRBG (may be null). </param>
		public HMacSP800DRBG(Mac hMac, int securityStrength, EntropySource entropySource, byte[] personalizationString, byte[] nonce)
		{
			if (securityStrength > Utils.getMaxSecurityStrength(hMac))
			{
				throw new IllegalArgumentException("Requested security strength is not supported by the derivation function");
			}

			if (entropySource.entropySize() < securityStrength)
			{
				throw new IllegalArgumentException("Not enough entropy for security strength required");
			}

			_securityStrength = securityStrength;
			_entropySource = entropySource;
			_hMac = hMac;

			byte[] entropy = getEntropy();
			byte[] seedMaterial = Arrays.concatenate(entropy, nonce, personalizationString);

			_K = new byte[hMac.getMacSize()];
			_V = new byte[_K.Length];
			Arrays.fill(_V, 1);

			hmac_DRBG_Update(seedMaterial);

			_reseedCounter = 1;
		}

		private void hmac_DRBG_Update(byte[] seedMaterial)
		{
			hmac_DRBG_Update_Func(seedMaterial, 0x00);
			if (seedMaterial != null)
			{
				hmac_DRBG_Update_Func(seedMaterial, 0x01);
			}
		}

		private void hmac_DRBG_Update_Func(byte[] seedMaterial, byte vValue)
		{
			_hMac.init(new KeyParameter(_K));

			_hMac.update(_V, 0, _V.Length);
			_hMac.update(vValue);

			if (seedMaterial != null)
			{
				_hMac.update(seedMaterial, 0, seedMaterial.Length);
			}

			_hMac.doFinal(_K, 0);

			_hMac.init(new KeyParameter(_K));
			_hMac.update(_V, 0, _V.Length);

			_hMac.doFinal(_V, 0);
		}

		/// <summary>
		/// Return the block size (in bits) of the DRBG.
		/// </summary>
		/// <returns> the number of bits produced on each round of the DRBG. </returns>
		public virtual int getBlockSize()
		{
			return _V.Length * 8;
		}

		/// <summary>
		/// Populate a passed in array with random data.
		/// </summary>
		/// <param name="output"> output array for generated bits. </param>
		/// <param name="additionalInput"> additional input to be added to the DRBG in this step. </param>
		/// <param name="predictionResistant"> true if a reseed should be forced, false otherwise.
		/// </param>
		/// <returns> number of bits generated, -1 if a reseed required. </returns>
		public virtual int generate(byte[] output, byte[] additionalInput, bool predictionResistant)
		{
			int numberOfBits = output.Length * 8;

			if (numberOfBits > MAX_BITS_REQUEST)
			{
				throw new IllegalArgumentException("Number of bits per request limited to " + MAX_BITS_REQUEST);
			}

			if (_reseedCounter > RESEED_MAX)
			{
				return -1;
			}

			if (predictionResistant)
			{
				reseed(additionalInput);
				additionalInput = null;
			}

			// 2.
			if (additionalInput != null)
			{
				hmac_DRBG_Update(additionalInput);
			}

			// 3.
			byte[] rv = new byte[output.Length];

			int m = output.Length / _V.Length;

			_hMac.init(new KeyParameter(_K));

			for (int i = 0; i < m; i++)
			{
				_hMac.update(_V, 0, _V.Length);
				_hMac.doFinal(_V, 0);

				JavaSystem.arraycopy(_V, 0, rv, i * _V.Length, _V.Length);
			}

			if (m * _V.Length < rv.Length)
			{
				_hMac.update(_V, 0, _V.Length);
				_hMac.doFinal(_V, 0);

				JavaSystem.arraycopy(_V, 0, rv, m * _V.Length, rv.Length - (m * _V.Length));
			}

			hmac_DRBG_Update(additionalInput);

			_reseedCounter++;

			JavaSystem.arraycopy(rv, 0, output, 0, output.Length);

			return numberOfBits;
		}

		/// <summary>
		/// Reseed the DRBG.
		/// </summary>
		/// <param name="additionalInput"> additional input to be added to the DRBG in this step. </param>
		public virtual void reseed(byte[] additionalInput)
		{
			byte[] entropy = getEntropy();
			byte[] seedMaterial = Arrays.concatenate(entropy, additionalInput);

			hmac_DRBG_Update(seedMaterial);

			_reseedCounter = 1;
		}

		private byte[] getEntropy()
		{
			byte[] entropy = _entropySource.getEntropy();

			if (entropy.Length < (_securityStrength + 7) / 8)
			{
				throw new IllegalStateException("Insufficient entropy provided by entropy source");
			}
			return entropy;
		}
	}

}