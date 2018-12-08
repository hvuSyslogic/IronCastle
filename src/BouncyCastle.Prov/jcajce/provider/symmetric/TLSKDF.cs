namespace org.bouncycastle.jcajce.provider.symmetric
{


	using Mac = org.bouncycastle.crypto.Mac;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;
	using SHA384Digest = org.bouncycastle.crypto.digests.SHA384Digest;
	using SHA512Digest = org.bouncycastle.crypto.digests.SHA512Digest;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using DigestFactory = org.bouncycastle.crypto.util.DigestFactory;
	using ConfigurableProvider = org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
	using BaseSecretKeyFactory = org.bouncycastle.jcajce.provider.symmetric.util.BaseSecretKeyFactory;
	using AlgorithmProvider = org.bouncycastle.jcajce.provider.util.AlgorithmProvider;
	using TLSKeyMaterialSpec = org.bouncycastle.jcajce.spec.TLSKeyMaterialSpec;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	public class TLSKDF
	{
		public class TLSKeyMaterialFactory : BaseSecretKeyFactory
		{
			public TLSKeyMaterialFactory(string algName) : base(algName, null)
			{
			}
		}

		public sealed class TLS10 : TLSKeyMaterialFactory
		{
			public TLS10() : base("TLS10KDF")
			{
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is TLSKeyMaterialSpec)
				{
					return new SecretKeySpec(PRF_legacy((TLSKeyMaterialSpec)keySpec), algName);
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}
		}

		public sealed class TLS11 : TLSKeyMaterialFactory
		{
			public TLS11() : base("TLS11KDF")
			{
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is TLSKeyMaterialSpec)
				{
					return new SecretKeySpec(PRF_legacy((TLSKeyMaterialSpec)keySpec), algName);
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}
		}

		private static byte[] PRF_legacy(TLSKeyMaterialSpec parameters)
		{
			Mac md5Hmac = new HMac(DigestFactory.createMD5());
			Mac sha1HMac = new HMac(DigestFactory.createSHA1());

			byte[] label = Strings.toByteArray(parameters.getLabel());
			byte[] labelSeed = Arrays.concatenate(label, parameters.getSeed());
			byte[] secret = parameters.getSecret();

			int s_half = (secret.Length + 1) / 2;
			byte[] s1 = new byte[s_half];
			byte[] s2 = new byte[s_half];
			JavaSystem.arraycopy(secret, 0, s1, 0, s_half);
			JavaSystem.arraycopy(secret, secret.Length - s_half, s2, 0, s_half);

			int size = parameters.getLength();
			byte[] b1 = new byte[size];
			byte[] b2 = new byte[size];

			hmac_hash(md5Hmac, s1, labelSeed, b1);
			hmac_hash(sha1HMac, s2, labelSeed, b2);

			for (int i = 0; i < size; i++)
			{
				b1[i] ^= b2[i];
			}
			return b1;
		}

		public class TLS12 : TLSKeyMaterialFactory
		{
			internal readonly Mac prf;

			public TLS12(string algName, Mac prf) : base(algName)
			{
				this.prf = prf;
			}

			public override SecretKey engineGenerateSecret(KeySpec keySpec)
			{
				if (keySpec is TLSKeyMaterialSpec)
				{
					return new SecretKeySpec(PRF((TLSKeyMaterialSpec)keySpec, prf), algName);
				}

				throw new InvalidKeySpecException("Invalid KeySpec");
			}

			public virtual byte[] PRF(TLSKeyMaterialSpec parameters, Mac prf)
			{
				byte[] label = Strings.toByteArray(parameters.getLabel());
				byte[] labelSeed = Arrays.concatenate(label, parameters.getSeed());
				byte[] secret = parameters.getSecret();

				byte[] buf = new byte[parameters.getLength()];

				hmac_hash(prf, secret, labelSeed, buf);

				return buf;
			}
		}

		public sealed class TLS12withSHA256 : TLS12
		{
			public TLS12withSHA256() : base("TLS12withSHA256KDF", new HMac(new SHA256Digest()))
			{
			}
		}

		public sealed class TLS12withSHA384 : TLS12
		{
			public TLS12withSHA384() : base("TLS12withSHA384KDF", new HMac(new SHA384Digest()))
			{
			}
		}

		public sealed class TLS12withSHA512 : TLS12
		{
			public TLS12withSHA512() : base("TLS12withSHA512KDF", new HMac(new SHA512Digest()))
			{
			}
		}

		private static void hmac_hash(Mac mac, byte[] secret, byte[] seed, byte[] @out)
		{
			mac.init(new KeyParameter(secret));
			byte[] a = seed;
			int size = mac.getMacSize();
			int iterations = (@out.Length + size - 1) / size;
			byte[] buf = new byte[mac.getMacSize()];
			byte[] buf2 = new byte[mac.getMacSize()];
			for (int i = 0; i < iterations; i++)
			{
				mac.update(a, 0, a.Length);
				mac.doFinal(buf, 0);
				a = buf;
				mac.update(a, 0, a.Length);
				mac.update(seed, 0, seed.Length);
				mac.doFinal(buf2, 0);
				JavaSystem.arraycopy(buf2, 0, @out, (size * i), Math.Min(size, @out.Length - (size * i)));
			}
		}

		public class Mappings : AlgorithmProvider
		{
			internal static readonly string PREFIX = typeof(TLSKDF).getName();

			public Mappings()
			{
			}

			public override void configure(ConfigurableProvider provider)
			{
				provider.addAlgorithm("SecretKeyFactory.TLS10KDF", PREFIX + "$TLS10");
				provider.addAlgorithm("SecretKeyFactory.TLS11KDF", PREFIX + "$TLS11");
				provider.addAlgorithm("SecretKeyFactory.TLS12WITHSHA256KDF", PREFIX + "$TLS12withSHA256");
				provider.addAlgorithm("SecretKeyFactory.TLS12WITHSHA384KDF", PREFIX + "$TLS12withSHA384");
				provider.addAlgorithm("SecretKeyFactory.TLS12WITHSHA512KDF", PREFIX + "$TLS12withSHA512");
			}
		}
	}

}