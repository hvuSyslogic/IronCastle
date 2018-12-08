using org.bouncycastle.asn1.pkcs;

namespace org.bouncycastle.pkcs.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using PKCS12PBEParams = org.bouncycastle.asn1.pkcs.PKCS12PBEParams;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using ExtendedDigest = org.bouncycastle.crypto.ExtendedDigest;
	using DESedeEngine = org.bouncycastle.crypto.engines.DESedeEngine;
	using RC2Engine = org.bouncycastle.crypto.engines.RC2Engine;
	using PKCS12ParametersGenerator = org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
	using MacOutputStream = org.bouncycastle.crypto.io.MacOutputStream;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using CBCBlockCipher = org.bouncycastle.crypto.modes.CBCBlockCipher;
	using PKCS7Padding = org.bouncycastle.crypto.paddings.PKCS7Padding;
	using PaddedBufferedBlockCipher = org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
	using DESedeParameters = org.bouncycastle.crypto.@params.DESedeParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using GenericKey = org.bouncycastle.@operator.GenericKey;
	using MacCalculator = org.bouncycastle.@operator.MacCalculator;
	using Integers = org.bouncycastle.util.Integers;

	public class PKCS12PBEUtils
	{
		private static Map keySizes = new HashMap();
		private static Set noIvAlgs = new HashSet();
		private static Set desAlgs = new HashSet();

		static PKCS12PBEUtils()
		{
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4, Integers.valueOf(128));
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4, Integers.valueOf(40));
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC, Integers.valueOf(192));
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC, Integers.valueOf(128));
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC2_CBC, Integers.valueOf(128));
			keySizes.put(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC, Integers.valueOf(40));

			noIvAlgs.add(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC4);
			noIvAlgs.add(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC4);

			desAlgs.add(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC);
			desAlgs.add(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC);
		}

		internal static int getKeySize(ASN1ObjectIdentifier algorithm)
		{
			return ((int?)keySizes.get(algorithm)).Value;
		}

		internal static bool hasNoIv(ASN1ObjectIdentifier algorithm)
		{
			return noIvAlgs.contains(algorithm);
		}

		internal static bool isDesAlg(ASN1ObjectIdentifier algorithm)
		{
			return desAlgs.contains(algorithm);
		}

		internal static PaddedBufferedBlockCipher getEngine(ASN1ObjectIdentifier algorithm)
		{
			BlockCipher engine;

			if (algorithm.Equals(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd3_KeyTripleDES_CBC) || algorithm.Equals(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd2_KeyTripleDES_CBC))
			{
				engine = new DESedeEngine();
			}
			else if (algorithm.Equals(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd128BitRC2_CBC) || algorithm.Equals(PKCSObjectIdentifiers_Fields.pbeWithSHAAnd40BitRC2_CBC))
			{
				engine = new RC2Engine();
			}
			else
			{
				throw new IllegalStateException("unknown algorithm");
			}

			return new PaddedBufferedBlockCipher(new CBCBlockCipher(engine), new PKCS7Padding());
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: static org.bouncycastle.operator.MacCalculator createMacCalculator(final org.bouncycastle.asn1.ASN1ObjectIdentifier digestAlgorithm, org.bouncycastle.crypto.ExtendedDigest digest, final org.bouncycastle.asn1.pkcs.PKCS12PBEParams pbeParams, final char[] password)
		internal static MacCalculator createMacCalculator(ASN1ObjectIdentifier digestAlgorithm, ExtendedDigest digest, PKCS12PBEParams pbeParams, char[] password)
		{
			PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(digest);

			pGen.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(password), pbeParams.getIV(), pbeParams.getIterations().intValue());

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.params.KeyParameter keyParam = (org.bouncycastle.crypto.params.KeyParameter)pGen.generateDerivedMacParameters(digest.getDigestSize() * 8);
			KeyParameter keyParam = (KeyParameter)pGen.generateDerivedMacParameters(digest.getDigestSize() * 8);

//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.macs.HMac hMac = new org.bouncycastle.crypto.macs.HMac(digest);
			HMac hMac = new HMac(digest);

			hMac.init(keyParam);

			return new MacCalculatorAnonymousInnerClass(digestAlgorithm, pbeParams, password, hMac);
		}

		public class MacCalculatorAnonymousInnerClass : MacCalculator
		{
			private ASN1ObjectIdentifier digestAlgorithm;
			private PKCS12PBEParams pbeParams;
			private char[] password;
			private HMac hMac;

			public MacCalculatorAnonymousInnerClass(ASN1ObjectIdentifier digestAlgorithm, PKCS12PBEParams pbeParams, char[] password, HMac hMac)
			{
				this.digestAlgorithm = digestAlgorithm;
				this.pbeParams = pbeParams;
				this.password = password;
				this.hMac = hMac;
			}

			public AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(digestAlgorithm, pbeParams);
			}

			public OutputStream getOutputStream()
			{
				return new MacOutputStream(hMac);
			}

			public byte[] getMac()
			{
				byte[] res = new byte[hMac.getMacSize()];

				hMac.doFinal(res, 0);

				return res;
			}

			public GenericKey getKey()
			{
				return new GenericKey(getAlgorithmIdentifier(), PKCS12ParametersGenerator.PKCS12PasswordToBytes(password));
			}
		}

		internal static CipherParameters createCipherParameters(ASN1ObjectIdentifier algorithm, ExtendedDigest digest, int blockSize, PKCS12PBEParams pbeParams, char[] password)
		{
			PKCS12ParametersGenerator pGen = new PKCS12ParametersGenerator(digest);

			pGen.init(PKCS12ParametersGenerator.PKCS12PasswordToBytes(password), pbeParams.getIV(), pbeParams.getIterations().intValue());

			CipherParameters @params;

			if (PKCS12PBEUtils.hasNoIv(algorithm))
			{
				@params = pGen.generateDerivedParameters(PKCS12PBEUtils.getKeySize(algorithm));
			}
			else
			{
				@params = pGen.generateDerivedParameters(PKCS12PBEUtils.getKeySize(algorithm), blockSize * 8);

				if (PKCS12PBEUtils.isDesAlg(algorithm))
				{
					DESedeParameters.setOddParity(((KeyParameter)((ParametersWithIV)@params).getParameters()).getKey());
				}
			}
			return @params;
		}
	}

}