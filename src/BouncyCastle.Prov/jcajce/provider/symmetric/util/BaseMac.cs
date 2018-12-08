using System;

namespace org.bouncycastle.jcajce.provider.symmetric.util
{


	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using Mac = org.bouncycastle.crypto.Mac;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using AEADParameters = org.bouncycastle.crypto.@params.AEADParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using RC2Parameters = org.bouncycastle.crypto.@params.RC2Parameters;
	using SkeinParameters = org.bouncycastle.crypto.@params.SkeinParameters;
	using AEADParameterSpec = org.bouncycastle.jcajce.spec.AEADParameterSpec;
	using SkeinParameterSpec = org.bouncycastle.jcajce.spec.SkeinParameterSpec;

	public class BaseMac : MacSpi, PBE
	{
		private static readonly Class gcmSpecClass = ClassUtil.loadClass(typeof(BaseMac), "javax.crypto.spec.GCMParameterSpec");

		private Mac macEngine;

		private int scheme = PBE_Fields.PKCS12;
		private int pbeHash = PBE_Fields.SHA1;
		private int keySize = 160;

		public BaseMac(Mac macEngine)
		{
			this.macEngine = macEngine;
		}

		public BaseMac(Mac macEngine, int scheme, int pbeHash, int keySize)
		{
			this.macEngine = macEngine;
			this.scheme = scheme;
			this.pbeHash = pbeHash;
			this.keySize = keySize;
		}

		public override void engineInit(Key key, AlgorithmParameterSpec @params)
		{
			CipherParameters param;

			if (key == null)
			{
				throw new InvalidKeyException("key is null");
			}

			if (key is PKCS12Key)
			{
				SecretKey k;
				PBEParameterSpec pbeSpec;

				try
				{
					k = (SecretKey)key;
				}
				catch (Exception)
				{
					throw new InvalidKeyException("PKCS12 requires a SecretKey/PBEKey");
				}

				try
				{
					pbeSpec = (PBEParameterSpec)@params;
				}
				catch (Exception)
				{
					throw new InvalidAlgorithmParameterException("PKCS12 requires a PBEParameterSpec");
				}

				if (k is PBEKey && pbeSpec == null)
				{
					pbeSpec = new PBEParameterSpec(((PBEKey)k).getSalt(), ((PBEKey)k).getIterationCount());
				}

				int digest = PBE_Fields.SHA1;
				int keySize = 160;
				if (macEngine.getAlgorithmName().StartsWith("GOST", StringComparison.Ordinal))
				{
					digest = PBE_Fields.GOST3411;
					keySize = 256;
				}
				else if (macEngine is HMac)
				{
					if (!macEngine.getAlgorithmName().StartsWith("SHA-1", StringComparison.Ordinal))
					{
						if (macEngine.getAlgorithmName().StartsWith("SHA-224", StringComparison.Ordinal))
						{
							digest = PBE_Fields.SHA224;
							keySize = 224;
						}
						else if (macEngine.getAlgorithmName().StartsWith("SHA-256", StringComparison.Ordinal))
						{
							digest = PBE_Fields.SHA256;
							keySize = 256;
						}
						else if (macEngine.getAlgorithmName().StartsWith("SHA-384", StringComparison.Ordinal))
						{
							digest = PBE_Fields.SHA384;
							keySize = 384;
						}
						else if (macEngine.getAlgorithmName().StartsWith("SHA-512", StringComparison.Ordinal))
						{
							digest = PBE_Fields.SHA512;
							keySize = 512;
						}
						else if (macEngine.getAlgorithmName().StartsWith("RIPEMD160", StringComparison.Ordinal))
						{
							digest = PBE_Fields.RIPEMD160;
							keySize = 160;
						}
						else
						{
							throw new InvalidAlgorithmParameterException("no PKCS12 mapping for HMAC: " + macEngine.getAlgorithmName());
						}
					}
				}
				// TODO: add correct handling for other digests
				param = PBE_Util.makePBEMacParameters(k, PBE_Fields.PKCS12, digest, keySize, pbeSpec);
			}
			else if (key is BCPBEKey)
			{
				BCPBEKey k = (BCPBEKey)key;

				if (k.getParam() != null)
				{
					param = k.getParam();
				}
				else if (@params is PBEParameterSpec)
				{
					param = PBE_Util.makePBEMacParameters(k, @params);
				}
				else
				{
					throw new InvalidAlgorithmParameterException("PBE requires PBE parameters to be set.");
				}
			}
			else
			{
				if (@params is PBEParameterSpec)
				{
					throw new InvalidAlgorithmParameterException("inappropriate parameter type: " + @params.GetType().getName());
				}
				param = new KeyParameter(key.getEncoded());
			}

			KeyParameter keyParam;
			if (param is ParametersWithIV)
			{
				keyParam = (KeyParameter)((ParametersWithIV)param).getParameters();
			}
			else
			{
				keyParam = (KeyParameter)param;
			}

			if (@params is AEADParameterSpec)
			{
				AEADParameterSpec aeadSpec = (AEADParameterSpec)@params;

				param = new AEADParameters(keyParam, aeadSpec.getMacSizeInBits(), aeadSpec.getNonce(), aeadSpec.getAssociatedData());
			}
			else if (@params is IvParameterSpec)
			{
				param = new ParametersWithIV(keyParam, ((IvParameterSpec)@params).getIV());
			}
			else if (@params is RC2ParameterSpec)
			{
				param = new ParametersWithIV(new RC2Parameters(keyParam.getKey(), ((RC2ParameterSpec)@params).getEffectiveKeyBits()), ((RC2ParameterSpec)@params).getIV());
			}
			else if (@params is SkeinParameterSpec)
			{
				param = (new SkeinParameters.Builder(copyMap(((SkeinParameterSpec)@params).getParameters()))).setKey(keyParam.getKey()).build();
			}
			else if (@params == null)
			{
				param = new KeyParameter(key.getEncoded());
			}
			else if (gcmSpecClass != null && gcmSpecClass.isAssignableFrom(@params.GetType()))
			{
				try
				{
					Method tLen = gcmSpecClass.getDeclaredMethod("getTLen", new Class[0]);
					Method iv = gcmSpecClass.getDeclaredMethod("getIV", new Class[0]);

					param = new AEADParameters(keyParam, ((int?)tLen.invoke(@params, new object[0])).Value, (byte[])iv.invoke(@params, new object[0]));
				}
				catch (Exception)
				{
					throw new InvalidAlgorithmParameterException("Cannot process GCMParameterSpec.");
				}
			}
			else if (!(@params is PBEParameterSpec))
			{
				throw new InvalidAlgorithmParameterException("unknown parameter type: " + @params.GetType().getName());
			}

			try
			{
				macEngine.init(param);
			}
			catch (Exception e)
			{
				throw new InvalidAlgorithmParameterException("cannot initialize MAC: " + e.Message);
			}
		}

		public override int engineGetMacLength()
		{
			return macEngine.getMacSize();
		}

		public override void engineReset()
		{
			macEngine.reset();
		}

		public override void engineUpdate(byte input)
		{
			macEngine.update(input);
		}

		public override void engineUpdate(byte[] input, int offset, int len)
		{
			macEngine.update(input, offset, len);
		}

		public override byte[] engineDoFinal()
		{
			byte[] @out = new byte[engineGetMacLength()];

			macEngine.doFinal(@out, 0);

			return @out;
		}

		private static Hashtable copyMap(Map paramsMap)
		{
			Hashtable newTable = new Hashtable();

			Iterator keys = paramsMap.keySet().iterator();
			while (keys.hasNext())
			{
				object key = keys.next();
				newTable.put(key, paramsMap.get(key));
			}

			return newTable;
		}
	}

}