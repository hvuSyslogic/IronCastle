using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.prng.drbg;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.prng
{

					
	/// <summary>
	/// Builder class for making SecureRandom objects based on SP 800-90A Deterministic Random Bit Generators (DRBG).
	/// </summary>
	public class SP800SecureRandomBuilder
	{
		private readonly SecureRandom random;
		private readonly EntropySourceProvider entropySourceProvider;

		private byte[] personalizationString;
		private int securityStrength = 256;
		private int entropyBitsRequired = 256;

		/// <summary>
		/// Basic constructor, creates a builder using an EntropySourceProvider based on the default SecureRandom with
		/// predictionResistant set to false.
		/// <para>
		/// Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
		/// the default SecureRandom does for its generateSeed() call.
		/// </para>
		/// </summary>
		public SP800SecureRandomBuilder() : this(CryptoServicesRegistrar.getSecureRandom(), false)
		{
		}

		/// <summary>
		/// Construct a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value
		/// for prediction resistance.
		/// <para>
		/// Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
		/// the passed in SecureRandom does for its generateSeed() call.
		/// </para> </summary>
		/// <param name="entropySource"> the SecureRandom acting as a source of entropy for DRBGs made by this builder. </param>
		/// <param name="predictionResistant"> true if the SecureRandom seeder can be regarded as predictionResistant. </param>
		public SP800SecureRandomBuilder(SecureRandom entropySource, bool predictionResistant)
		{
			this.random = entropySource;
			this.entropySourceProvider = new BasicEntropySourceProvider(random, predictionResistant);
		}

		/// <summary>
		/// Create a builder which makes creates the SecureRandom objects from a specified entropy source provider.
		/// <para>
		/// <b>Note:</b> If this constructor is used any calls to setSeed() in the resulting SecureRandom will be ignored.
		/// </para> </summary>
		/// <param name="entropySourceProvider"> a provider of EntropySource objects. </param>
		public SP800SecureRandomBuilder(EntropySourceProvider entropySourceProvider)
		{
			this.random = null;
			this.entropySourceProvider = entropySourceProvider;
		}

		/// <summary>
		/// Set the personalization string for DRBG SecureRandoms created by this builder </summary>
		/// <param name="personalizationString">  the personalisation string for the underlying DRBG. </param>
		/// <returns> the current builder. </returns>
		public virtual SP800SecureRandomBuilder setPersonalizationString(byte[] personalizationString)
		{
			this.personalizationString = Arrays.clone(personalizationString);

			return this;
		}

		/// <summary>
		/// Set the security strength required for DRBGs used in building SecureRandom objects.
		/// </summary>
		/// <param name="securityStrength"> the security strength (in bits) </param>
		/// <returns> the current builder. </returns>
		public virtual SP800SecureRandomBuilder setSecurityStrength(int securityStrength)
		{
			this.securityStrength = securityStrength;

			return this;
		}

		/// <summary>
		/// Set the amount of entropy bits required for seeding and reseeding DRBGs used in building SecureRandom objects.
		/// </summary>
		/// <param name="entropyBitsRequired"> the number of bits of entropy to be requested from the entropy source on each seed/reseed. </param>
		/// <returns> the current builder. </returns>
		public virtual SP800SecureRandomBuilder setEntropyBitsRequired(int entropyBitsRequired)
		{
			this.entropyBitsRequired = entropyBitsRequired;

			return this;
		}

		/// <summary>
		/// Build a SecureRandom based on a SP 800-90A Hash DRBG.
		/// </summary>
		/// <param name="digest"> digest algorithm to use in the DRBG underneath the SecureRandom. </param>
		/// <param name="nonce">  nonce value to use in DRBG construction. </param>
		/// <param name="predictionResistant"> specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes. </param>
		/// <returns> a SecureRandom supported by a Hash DRBG. </returns>
		public virtual SP800SecureRandom buildHash(Digest digest, byte[] nonce, bool predictionResistant)
		{
			return new SP800SecureRandom(random, entropySourceProvider.get(entropyBitsRequired), new HashDRBGProvider(digest, nonce, personalizationString, securityStrength), predictionResistant);
		}

		/// <summary>
		/// Build a SecureRandom based on a SP 800-90A CTR DRBG.
		/// </summary>
		/// <param name="cipher"> the block cipher to base the DRBG on. </param>
		/// <param name="keySizeInBits"> key size in bits to be used with the block cipher. </param>
		/// <param name="nonce"> nonce value to use in DRBG construction. </param>
		/// <param name="predictionResistant">  specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes. </param>
		/// <returns>  a SecureRandom supported by a CTR DRBG. </returns>
		public virtual SP800SecureRandom buildCTR(BlockCipher cipher, int keySizeInBits, byte[] nonce, bool predictionResistant)
		{
			return new SP800SecureRandom(random, entropySourceProvider.get(entropyBitsRequired), new CTRDRBGProvider(cipher, keySizeInBits, nonce, personalizationString, securityStrength), predictionResistant);
		}

		/// <summary>
		/// Build a SecureRandom based on a SP 800-90A HMAC DRBG.
		/// </summary>
		/// <param name="hMac"> HMAC algorithm to use in the DRBG underneath the SecureRandom. </param>
		/// <param name="nonce">  nonce value to use in DRBG construction. </param>
		/// <param name="predictionResistant"> specify whether the underlying DRBG in the resulting SecureRandom should reseed on each request for bytes. </param>
		/// <returns> a SecureRandom supported by a HMAC DRBG. </returns>
		public virtual SP800SecureRandom buildHMAC(Mac hMac, byte[] nonce, bool predictionResistant)
		{
			return new SP800SecureRandom(random, entropySourceProvider.get(entropyBitsRequired), new HMacDRBGProvider(hMac, nonce, personalizationString, securityStrength), predictionResistant);
		}

		public class HashDRBGProvider : DRBGProvider
		{
			internal readonly Digest digest;
			internal readonly byte[] nonce;
			internal readonly byte[] personalizationString;
			internal readonly int securityStrength;

			public HashDRBGProvider(Digest digest, byte[] nonce, byte[] personalizationString, int securityStrength)
			{
				this.digest = digest;
				this.nonce = nonce;
				this.personalizationString = personalizationString;
				this.securityStrength = securityStrength;
			}

			public virtual SP80090DRBG get(EntropySource entropySource)
			{
				return new HashSP800DRBG(digest, securityStrength, entropySource, personalizationString, nonce);
			}
		}

		public class HMacDRBGProvider : DRBGProvider
		{
			internal readonly Mac hMac;
			internal readonly byte[] nonce;
			internal readonly byte[] personalizationString;
			internal readonly int securityStrength;

			public HMacDRBGProvider(Mac hMac, byte[] nonce, byte[] personalizationString, int securityStrength)
			{
				this.hMac = hMac;
				this.nonce = nonce;
				this.personalizationString = personalizationString;
				this.securityStrength = securityStrength;
			}

			public virtual SP80090DRBG get(EntropySource entropySource)
			{
				return new HMacSP800DRBG(hMac, securityStrength, entropySource, personalizationString, nonce);
			}
		}

		public class CTRDRBGProvider : DRBGProvider
		{

			internal readonly BlockCipher blockCipher;
			internal readonly int keySizeInBits;
			internal readonly byte[] nonce;
			internal readonly byte[] personalizationString;
			internal readonly int securityStrength;

			public CTRDRBGProvider(BlockCipher blockCipher, int keySizeInBits, byte[] nonce, byte[] personalizationString, int securityStrength)
			{
				this.blockCipher = blockCipher;
				this.keySizeInBits = keySizeInBits;
				this.nonce = nonce;
				this.personalizationString = personalizationString;
				this.securityStrength = securityStrength;
			}

			public virtual SP80090DRBG get(EntropySource entropySource)
			{
				return new CTRSP800DRBG(blockCipher, keySizeInBits, securityStrength, entropySource, personalizationString, nonce);
			}
		}
	}

}