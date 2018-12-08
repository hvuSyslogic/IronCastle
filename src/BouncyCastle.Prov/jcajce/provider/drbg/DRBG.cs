using System;

namespace org.bouncycastle.jcajce.provider.drbg
{

	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using EntropySource = org.bouncycastle.crypto.prng.EntropySource;
	using EntropySourceProvider = org.bouncycastle.crypto.prng.EntropySourceProvider;
	using SP800SecureRandom = org.bouncycastle.crypto.prng.SP800SecureRandom;
	using SP800SecureRandomBuilder = org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using ClassUtil = org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
	using AsymmetricAlgorithmProvider = org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
	using Arrays = org.bouncycastle.util.Arrays;
	using Pack = org.bouncycastle.util.Pack;
	using Strings = org.bouncycastle.util.Strings;

	public class DRBG
	{
		private static readonly string PREFIX = typeof(DRBG).getName();

		// {"Provider class name","SecureRandomSpi class name"}
		private static readonly string[][] initialEntropySourceNames = new string[][]
		{
			new string[] {"sun.security.provider.Sun", "sun.security.provider.SecureRandom"},
			new string[] {"org.apache.harmony.security.provider.crypto.CryptoProvider", "org.apache.harmony.security.provider.crypto.SHA1PRNG_SecureRandomImpl"},
			new string[] {"com.android.org.conscrypt.OpenSSLProvider", "com.android.org.conscrypt.OpenSSLRandom"},
			new string[] {"org.conscrypt.OpenSSLProvider", "org.conscrypt.OpenSSLRandom"}
		};

		private static readonly object[] initialEntropySourceAndSpi = findSource();

		// Cascade through providers looking for match.
		private static object[] findSource()
		{
			for (int t = 0; t < initialEntropySourceNames.Length; t++)
			{
				string[] pair = initialEntropySourceNames[t];
				try
				{
					object[] r = new object[]{Class.forName(pair[0]).newInstance(), Class.forName(pair[1]).newInstance()};

					return r;
				}
				catch (Exception)
				{
					continue;
				}
			}

			return null;
		}

		public class CoreSecureRandom : SecureRandom
		{
			public CoreSecureRandom() : base((SecureRandomSpi)initialEntropySourceAndSpi[1], (Provider)initialEntropySourceAndSpi[0])
			{
			}
		}

		// unfortunately new SecureRandom() can cause a regress and it's the only reliable way of getting access
		// to the JVM's seed generator.
		private static SecureRandom createInitialEntropySource()
		{
			bool hasGetInstanceStrong = AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass());

			if (hasGetInstanceStrong)
			{
				return AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass2());
			}
			else
			{
				return createCoreSecureRandom();
			}
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction<bool>
		{
			public bool? run()
			{
				try
				{
					Class def = typeof(SecureRandom);

					return def.getMethod("getInstanceStrong") != null;
				}
				catch (Exception)
				{
					return false;
				}
			}
		}

		public class PrivilegedActionAnonymousInnerClass2 : PrivilegedAction<SecureRandom>
		{
			public SecureRandom run()
			{
				try
				{
					return (SecureRandom)typeof(SecureRandom).getMethod("getInstanceStrong").invoke(null);
				}
				catch (Exception)
				{
					return createCoreSecureRandom();
				}
			}
		}

		private static SecureRandom createCoreSecureRandom()
		{
			if (initialEntropySourceAndSpi != null)
			{
				return new CoreSecureRandom();
			}
			else
			{
				try
				{
					string source = Security.getProperty("securerandom.source");

					return new URLSeededSecureRandom(new URL(source));
				}
				catch (Exception)
				{
					return new SecureRandom(); // we're desperate, it's worth a try.
				}
			}
		}

		private static EntropySourceProvider createEntropySource()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String sourceClass = System.getProperty("org.bouncycastle.drbg.entropysource");
			string sourceClass = System.getProperty("org.bouncycastle.drbg.entropysource");

			return AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass3(sourceClass));
		}

		public class PrivilegedActionAnonymousInnerClass3 : PrivilegedAction<EntropySourceProvider>
		{
			private string sourceClass;

			public PrivilegedActionAnonymousInnerClass3(string sourceClass)
			{
				this.sourceClass = sourceClass;
			}

			public EntropySourceProvider run()
			{
				try
				{
					Class clazz = ClassUtil.loadClass(typeof(DRBG), sourceClass);

					return (EntropySourceProvider)clazz.newInstance();
				}
				catch (Exception e)
				{
					throw new IllegalStateException("entropy source " + sourceClass + " not created: " + e.Message, e);
				}
			}
		}

		private static SecureRandom createBaseRandom(bool isPredictionResistant)
		{
			if (System.getProperty("org.bouncycastle.drbg.entropysource") != null)
			{
				EntropySourceProvider entropyProvider = createEntropySource();

				EntropySource initSource = entropyProvider.get(16 * 8);

				byte[] personalisationString = isPredictionResistant ? generateDefaultPersonalizationString(initSource.getEntropy()) : generateNonceIVPersonalizationString(initSource.getEntropy());

				return (new SP800SecureRandomBuilder(entropyProvider)).setPersonalizationString(personalisationString).buildHash(new SHA512Digest(), Arrays.concatenate(initSource.getEntropy(), initSource.getEntropy()), isPredictionResistant);
			}
			else
			{
				SecureRandom randomSource = new HybridSecureRandom(); // needs to be done late, can't use static

				byte[] personalisationString = isPredictionResistant ? generateDefaultPersonalizationString(randomSource.generateSeed(16)) : generateNonceIVPersonalizationString(randomSource.generateSeed(16));

				return (new SP800SecureRandomBuilder(randomSource, true)).setPersonalizationString(personalisationString).buildHash(new SHA512Digest(), randomSource.generateSeed(32), isPredictionResistant);
			}
		}

		public class Default : SecureRandomSpi
		{
			internal static readonly SecureRandom random = createBaseRandom(true);

			public Default()
			{
			}

			public virtual void engineSetSeed(byte[] bytes)
			{
				random.setSeed(bytes);
			}

			public virtual void engineNextBytes(byte[] bytes)
			{
				random.nextBytes(bytes);
			}

			public virtual byte[] engineGenerateSeed(int numBytes)
			{
				return random.generateSeed(numBytes);
			}
		}

		public class NonceAndIV : SecureRandomSpi
		{
			internal static readonly SecureRandom random = createBaseRandom(false);

			public NonceAndIV()
			{
			}

			public virtual void engineSetSeed(byte[] bytes)
			{
				random.setSeed(bytes);
			}

			public virtual void engineNextBytes(byte[] bytes)
			{
				random.nextBytes(bytes);
			}

			public virtual byte[] engineGenerateSeed(int numBytes)
			{
				return random.generateSeed(numBytes);
			}
		}

		public class Mappings : AsymmetricAlgorithmProvider
		{
			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("SecureRandom.DEFAULT", PREFIX + "$Default");
				provider.addAlgorithm("SecureRandom.NONCEANDIV", PREFIX + "$NonceAndIV");
			}
		}

		private static byte[] generateDefaultPersonalizationString(byte[] seed)
		{
			return Arrays.concatenate(Strings.toByteArray("Default"), seed, Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
		}

		private static byte[] generateNonceIVPersonalizationString(byte[] seed)
		{
			return Arrays.concatenate(Strings.toByteArray("Nonce"), seed, Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
		}

		public class HybridRandomProvider : Provider
		{
			public HybridRandomProvider() : base("BCHEP", 1.0, "Bouncy Castle Hybrid Entropy Provider")
			{
			}
		}

		public class URLSeededSecureRandom : SecureRandom
		{
			internal readonly InputStream seedStream;

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: URLSeededSecureRandom(final java.net.URL url)
			public URLSeededSecureRandom(URL url) : base(null, new HybridRandomProvider())
			{

				this.seedStream = AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass(this, url));
			}

			public class PrivilegedActionAnonymousInnerClass : PrivilegedAction<InputStream>
			{
				private readonly URLSeededSecureRandom outerInstance;

				private URL url;

				public PrivilegedActionAnonymousInnerClass(URLSeededSecureRandom outerInstance, URL url)
				{
					this.outerInstance = outerInstance;
					this.url = url;
				}

				public InputStream run()
				{
					try
					{
						return url.openStream();
					}
					catch (IOException)
					{
						throw new InternalError("unable to open random source");
					}
				}
			}

			public virtual void setSeed(byte[] seed)
			{
				// ignore
			}

			public virtual void setSeed(long seed)
			{
				// ignore
			}

			public virtual byte[] generateSeed(int numBytes)
			{
				lock (this)
				{
					byte[] data = new byte[numBytes];

					int off = 0;
					int len;

					while (off != data.Length && (len = privilegedRead(data, off, data.Length - off)) > -1)
					{
						off += len;
					}

					if (off != data.Length)
					{
						throw new InternalError("unable to fully read random source");
					}

					return data;
				}
			}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: private int privilegedRead(final byte[] data, final int off, final int len)
			public virtual int privilegedRead(byte[] data, int off, int len)
			{
				return AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass2(this, data, off, len));
			}

			public class PrivilegedActionAnonymousInnerClass2 : PrivilegedAction<int>
			{
				private readonly URLSeededSecureRandom outerInstance;

				private byte[] data;
				private int off;
				private int len;

				public PrivilegedActionAnonymousInnerClass2(URLSeededSecureRandom outerInstance, byte[] data, int off, int len)
				{
					this.outerInstance = outerInstance;
					this.data = data;
					this.off = off;
					this.len = len;
				}

				public int? run()
				{
					try
					{
						return outerInstance.seedStream.read(data, off, len);
					}
					catch (IOException)
					{
						throw new InternalError("unable to read random source");
					}
				}
			}
		}

		public class HybridSecureRandom : SecureRandom
		{
			internal readonly AtomicBoolean seedAvailable = new AtomicBoolean(false);
			internal readonly AtomicInteger samples = new AtomicInteger(0);
			internal readonly SecureRandom baseRandom = createInitialEntropySource();

			internal readonly SP800SecureRandom drbg;

			public HybridSecureRandom() : base(null, new HybridRandomProvider())
			{
				drbg = new SP800SecureRandomBuilder(new EntropySourceProviderAnonymousInnerClass(this))
				   .setPersonalizationString(Strings.toByteArray("Bouncy Castle Hybrid Entropy Source")).buildHMAC(new HMac(new SHA512Digest()), baseRandom.generateSeed(32), false); // 32 byte nonce
			}

			public class EntropySourceProviderAnonymousInnerClass : EntropySourceProvider
			{
				private readonly HybridSecureRandom outerInstance;

				public EntropySourceProviderAnonymousInnerClass(HybridSecureRandom outerInstance)
				{
					this.outerInstance = outerInstance;
				}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.crypto.prng.EntropySource get(final int bitsRequired)
				public EntropySource get(int bitsRequired)
				{
					return new SignallingEntropySource(outerInstance, bitsRequired);
				}
			}

			public virtual void setSeed(byte[] seed)
			{
				if (drbg != null)
				{
					drbg.setSeed(seed);
				}
			}

			public virtual void setSeed(long seed)
			{
				if (drbg != null)
				{
					drbg.setSeed(seed);
				}
			}

			public virtual byte[] generateSeed(int numBytes)
			{
				byte[] data = new byte[numBytes];

				// after 20 samples we'll start to check if there is new seed material.
				if (samples.getAndIncrement() > 20)
				{
					if (seedAvailable.getAndSet(false))
					{
						samples.set(0);
						drbg.reseed((byte[])null); // need for Java 1.9
					}
				}

				drbg.nextBytes(data);

				return data;
			}

			public class SignallingEntropySource : EntropySource
			{
				private readonly DRBG.HybridSecureRandom outerInstance;

				internal readonly int byteLength;
				internal readonly AtomicReference entropy = new AtomicReference();
				internal readonly AtomicBoolean scheduled = new AtomicBoolean(false);

				public SignallingEntropySource(DRBG.HybridSecureRandom outerInstance, int bitsRequired)
				{
					this.outerInstance = outerInstance;
					this.byteLength = (bitsRequired + 7) / 8;
				}

				public virtual bool isPredictionResistant()
				{
					return true;
				}

				public virtual byte[] getEntropy()
				{
					byte[] seed = (byte[])entropy.getAndSet(null);

					if (seed == null || seed.Length != byteLength)
					{
						seed = outerInstance.baseRandom.generateSeed(byteLength);
					}
					else
					{
						scheduled.set(false);
					}

					if (!scheduled.getAndSet(true))
					{
						(new Thread(new EntropyGatherer(this, byteLength))).start();
					}

					return seed;
				}

				public virtual int entropySize()
				{
					return byteLength * 8;
				}

				public class EntropyGatherer : Runnable
				{
					private readonly DRBG.HybridSecureRandom.SignallingEntropySource outerInstance;

					internal readonly int numBytes;

					public EntropyGatherer(DRBG.HybridSecureRandom.SignallingEntropySource outerInstance, int numBytes)
					{
						this.outerInstance = outerInstance;
						this.numBytes = numBytes;
					}

					public virtual void run()
					{
						outerInstance.entropy.set(outerInstance.outerInstance.baseRandom.generateSeed(numBytes));
						outerInstance.outerInstance.seedAvailable.set(true);
					}
				}
			}
		}
	}

}