using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.@params;
using org.bouncycastle.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.prng
{

			
	public class X931SecureRandomBuilder
	{
		private SecureRandom random; // JDK 1.1 complains on final.
		private EntropySourceProvider entropySourceProvider;

		private byte[] dateTimeVector;

		/// <summary>
		/// Basic constructor, creates a builder using an EntropySourceProvider based on the default SecureRandom with
		/// predictionResistant set to false.
		/// <para>
		/// Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
		/// the default SecureRandom does for its generateSeed() call.
		/// </para>
		/// </summary>
		public X931SecureRandomBuilder() : this(CryptoServicesRegistrar.getSecureRandom(), false)
		{
		}

		/// <summary>
		/// Construct a builder with an EntropySourceProvider based on the passed in SecureRandom and the passed in value
		/// for prediction resistance.
		/// <para>
		/// Any SecureRandom created from a builder constructed like this will make use of input passed to SecureRandom.setSeed() if
		/// the passed in SecureRandom does for its generateSeed() call.
		/// </para> </summary>
		/// <param name="entropySource"> </param>
		/// <param name="predictionResistant"> </param>
		public X931SecureRandomBuilder(SecureRandom entropySource, bool predictionResistant)
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
		public X931SecureRandomBuilder(EntropySourceProvider entropySourceProvider)
		{
			this.random = null;
			this.entropySourceProvider = entropySourceProvider;
		}

		public virtual X931SecureRandomBuilder setDateTimeVector(byte[] dateTimeVector)
		{
			this.dateTimeVector = Arrays.clone(dateTimeVector);

			return this;
		}

		/// <summary>
		/// Construct a X9.31 secure random generator using the passed in engine and key. If predictionResistant is true the
		/// generator will be reseeded on each request.
		/// </summary>
		/// <param name="engine"> a block cipher to use as the operator. </param>
		/// <param name="key"> the block cipher key to initialise engine with. </param>
		/// <param name="predictionResistant"> true if engine to be reseeded on each use, false otherwise. </param>
		/// <returns> a SecureRandom. </returns>
		public virtual X931SecureRandom build(BlockCipher engine, KeyParameter key, bool predictionResistant)
		{
			if (dateTimeVector == null)
			{
				dateTimeVector = new byte[engine.getBlockSize()];
				Pack.longToBigEndian(JavaSystem.currentTimeMillis(), dateTimeVector, 0);
			}

			engine.init(true, key);

			return new X931SecureRandom(random, new X931RNG(engine, dateTimeVector, entropySourceProvider.get(engine.getBlockSize() * 8)), predictionResistant);
		}
	}

}