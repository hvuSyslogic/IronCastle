namespace org.bouncycastle.openpgp.@operator.bc
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ECNamedCurveTable = org.bouncycastle.asn1.x9.ECNamedCurveTable;
	using X9ECParameters = org.bouncycastle.asn1.x9.X9ECParameters;
	using BlockCipher = org.bouncycastle.crypto.BlockCipher;
	using BufferedBlockCipher = org.bouncycastle.crypto.BufferedBlockCipher;
	using CustomNamedCurves = org.bouncycastle.crypto.ec.CustomNamedCurves;
	using CipherInputStream = org.bouncycastle.crypto.io.CipherInputStream;
	using CFBBlockCipher = org.bouncycastle.crypto.modes.CFBBlockCipher;
	using OpenPGPCFBBlockCipher = org.bouncycastle.crypto.modes.OpenPGPCFBBlockCipher;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using ParametersWithIV = org.bouncycastle.crypto.@params.ParametersWithIV;
	using ECAlgorithms = org.bouncycastle.math.ec.ECAlgorithms;
	using ECCurve = org.bouncycastle.math.ec.ECCurve;
	using ECPoint = org.bouncycastle.math.ec.ECPoint;
	using BigIntegers = org.bouncycastle.util.BigIntegers;

	public class BcUtil
	{
		internal static BufferedBlockCipher createStreamCipher(bool forEncryption, BlockCipher engine, bool withIntegrityPacket, byte[] key)
		{
			BufferedBlockCipher c;

			if (withIntegrityPacket)
			{
				c = new BufferedBlockCipher(new CFBBlockCipher(engine, engine.getBlockSize() * 8));
			}
			else
			{
				c = new BufferedBlockCipher(new OpenPGPCFBBlockCipher(engine));
			}

			KeyParameter keyParameter = new KeyParameter(key);

			if (withIntegrityPacket)
			{
				c.init(forEncryption, new ParametersWithIV(keyParameter, new byte[engine.getBlockSize()]));
			}
			else
			{
				c.init(forEncryption, keyParameter);
			}

			return c;
		}

		public static PGPDataDecryptor createDataDecryptor(bool withIntegrityPacket, BlockCipher engine, byte[] key)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.crypto.BufferedBlockCipher c = createStreamCipher(false, engine, withIntegrityPacket, key);
			BufferedBlockCipher c = createStreamCipher(false, engine, withIntegrityPacket, key);

			return new PGPDataDecryptorAnonymousInnerClass(c);
		}

		public class PGPDataDecryptorAnonymousInnerClass : PGPDataDecryptor
		{
			private BufferedBlockCipher c;

			public PGPDataDecryptorAnonymousInnerClass(BufferedBlockCipher c)
			{
				this.c = c;
			}

			public InputStream getInputStream(InputStream @in)
			{
				return new CipherInputStream(@in, c);
			}

			public int getBlockSize()
			{
				return c.getBlockSize();
			}

			public PGPDigestCalculator getIntegrityCalculator()
			{
				return new SHA1PGPDigestCalculator();
			}
		}

		public static BufferedBlockCipher createSymmetricKeyWrapper(bool forEncryption, BlockCipher engine, byte[] key, byte[] iv)
		{
			BufferedBlockCipher c = new BufferedBlockCipher(new CFBBlockCipher(engine, engine.getBlockSize() * 8));

			c.init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));

			return c;
		}

		internal static X9ECParameters getX9Parameters(ASN1ObjectIdentifier curveOID)
		{
			X9ECParameters x9 = CustomNamedCurves.getByOID(curveOID);
			if (x9 == null)
			{
				x9 = ECNamedCurveTable.getByOID(curveOID);
			}

			return x9;
		}

		internal static ECPoint decodePoint(BigInteger encodedPoint, ECCurve curve)
		{
			return curve.decodePoint(BigIntegers.asUnsignedByteArray(encodedPoint));
		}
	}

}