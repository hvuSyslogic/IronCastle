namespace org.bouncycastle.jcajce.provider.test
{

	using Assert = junit.framework.Assert;
	using TestCase = junit.framework.TestCase;
	using GOST3411 = org.bouncycastle.jcajce.provider.digest.GOST3411;
	using MD2 = org.bouncycastle.jcajce.provider.digest.MD2;
	using MD4 = org.bouncycastle.jcajce.provider.digest.MD4;
	using MD5 = org.bouncycastle.jcajce.provider.digest.MD5;
	using RIPEMD128 = org.bouncycastle.jcajce.provider.digest.RIPEMD128;
	using RIPEMD160 = org.bouncycastle.jcajce.provider.digest.RIPEMD160;
	using RIPEMD256 = org.bouncycastle.jcajce.provider.digest.RIPEMD256;
	using RIPEMD320 = org.bouncycastle.jcajce.provider.digest.RIPEMD320;
	using SHA1 = org.bouncycastle.jcajce.provider.digest.SHA1;
	using SHA224 = org.bouncycastle.jcajce.provider.digest.SHA224;
	using SHA256 = org.bouncycastle.jcajce.provider.digest.SHA256;
	using SHA3 = org.bouncycastle.jcajce.provider.digest.SHA3;
	using SHA384 = org.bouncycastle.jcajce.provider.digest.SHA384;
	using SHA512 = org.bouncycastle.jcajce.provider.digest.SHA512;
	using SM3 = org.bouncycastle.jcajce.provider.digest.SM3;
	using Tiger = org.bouncycastle.jcajce.provider.digest.Tiger;
	using Whirlpool = org.bouncycastle.jcajce.provider.digest.Whirlpool;
	using AES = org.bouncycastle.jcajce.provider.symmetric.AES;
	using ARC4 = org.bouncycastle.jcajce.provider.symmetric.ARC4;
	using Blowfish = org.bouncycastle.jcajce.provider.symmetric.Blowfish;
	using CAST5 = org.bouncycastle.jcajce.provider.symmetric.CAST5;
	using CAST6 = org.bouncycastle.jcajce.provider.symmetric.CAST6;
	using Camellia = org.bouncycastle.jcajce.provider.symmetric.Camellia;
	using ChaCha = org.bouncycastle.jcajce.provider.symmetric.ChaCha;
	using DES = org.bouncycastle.jcajce.provider.symmetric.DES;
	using DESede = org.bouncycastle.jcajce.provider.symmetric.DESede;
	using GOST28147 = org.bouncycastle.jcajce.provider.symmetric.GOST28147;
	using Grain128 = org.bouncycastle.jcajce.provider.symmetric.Grain128;
	using Grainv1 = org.bouncycastle.jcajce.provider.symmetric.Grainv1;
	using HC128 = org.bouncycastle.jcajce.provider.symmetric.HC128;
	using HC256 = org.bouncycastle.jcajce.provider.symmetric.HC256;
	using IDEA = org.bouncycastle.jcajce.provider.symmetric.IDEA;
	using Noekeon = org.bouncycastle.jcajce.provider.symmetric.Noekeon;
	using PBEPBKDF2 = org.bouncycastle.jcajce.provider.symmetric.PBEPBKDF2;
	using PBEPKCS12 = org.bouncycastle.jcajce.provider.symmetric.PBEPKCS12;
	using RC2 = org.bouncycastle.jcajce.provider.symmetric.RC2;
	using RC5 = org.bouncycastle.jcajce.provider.symmetric.RC5;
	using RC6 = org.bouncycastle.jcajce.provider.symmetric.RC6;
	using Rijndael = org.bouncycastle.jcajce.provider.symmetric.Rijndael;
	using SEED = org.bouncycastle.jcajce.provider.symmetric.SEED;
	using Salsa20 = org.bouncycastle.jcajce.provider.symmetric.Salsa20;
	using Serpent = org.bouncycastle.jcajce.provider.symmetric.Serpent;
	using Skipjack = org.bouncycastle.jcajce.provider.symmetric.Skipjack;
	using TEA = org.bouncycastle.jcajce.provider.symmetric.TEA;
	using Twofish = org.bouncycastle.jcajce.provider.symmetric.Twofish;
	using VMPC = org.bouncycastle.jcajce.provider.symmetric.VMPC;
	using VMPCKSA3 = org.bouncycastle.jcajce.provider.symmetric.VMPCKSA3;
	using XSalsa20 = org.bouncycastle.jcajce.provider.symmetric.XSalsa20;
	using XTEA = org.bouncycastle.jcajce.provider.symmetric.XTEA;

	public class PrivateConstructorTest : TestCase
	{
		public virtual void testSymmetric()
		{
			evilNoConstructionTest(typeof(AES));
			evilNoConstructionTest(typeof(ARC4));
			evilNoConstructionTest(typeof(Blowfish));
			evilNoConstructionTest(typeof(Camellia));
			evilNoConstructionTest(typeof(CAST5));
			evilNoConstructionTest(typeof(CAST6));
			evilNoConstructionTest(typeof(DESede));
			evilNoConstructionTest(typeof(DES));
			evilNoConstructionTest(typeof(GOST28147));
			evilNoConstructionTest(typeof(Grain128));
			evilNoConstructionTest(typeof(Grainv1));
			evilNoConstructionTest(typeof(HC128));
			evilNoConstructionTest(typeof(HC256));
			evilNoConstructionTest(typeof(IDEA));
			evilNoConstructionTest(typeof(Noekeon));
			evilNoConstructionTest(typeof(PBEPBKDF2));
			evilNoConstructionTest(typeof(PBEPKCS12));
			evilNoConstructionTest(typeof(RC2));
			evilNoConstructionTest(typeof(RC5));
			evilNoConstructionTest(typeof(RC6));
			evilNoConstructionTest(typeof(Rijndael));
			evilNoConstructionTest(typeof(ChaCha));
			evilNoConstructionTest(typeof(Salsa20));
			evilNoConstructionTest(typeof(XSalsa20));
			evilNoConstructionTest(typeof(SEED));
			evilNoConstructionTest(typeof(Serpent));
			evilNoConstructionTest(typeof(Skipjack));
			evilNoConstructionTest(typeof(TEA));
			evilNoConstructionTest(typeof(Twofish));
			evilNoConstructionTest(typeof(VMPC));
			evilNoConstructionTest(typeof(VMPCKSA3));
			evilNoConstructionTest(typeof(XTEA));
		}

		public virtual void testDigest()
		{
			evilNoConstructionTest(typeof(GOST3411));
			evilNoConstructionTest(typeof(MD2));
			evilNoConstructionTest(typeof(MD4));
			evilNoConstructionTest(typeof(MD5));
			evilNoConstructionTest(typeof(RIPEMD128));
			evilNoConstructionTest(typeof(RIPEMD160));
			evilNoConstructionTest(typeof(RIPEMD256));
			evilNoConstructionTest(typeof(RIPEMD320));
			evilNoConstructionTest(typeof(SHA1));
			evilNoConstructionTest(typeof(SHA224));
			evilNoConstructionTest(typeof(SHA256));
			evilNoConstructionTest(typeof(SHA384));
			evilNoConstructionTest(typeof(SHA3));
			evilNoConstructionTest(typeof(SHA512));
			evilNoConstructionTest(typeof(SM3));
			evilNoConstructionTest(typeof(Tiger));
			evilNoConstructionTest(typeof(Whirlpool));
		}

		private static void evilNoConstructionTest(Class clazz)
		{
			Constructor[] constructors = clazz.getDeclaredConstructors();
			Assert.assertEquals("Class should only have one constructor", 1, constructors.Length);
			Constructor constructor = constructors[0];
			Assert.assertEquals("Constructor should be private", Modifier.PRIVATE, constructor.getModifiers());
			Assert.assertFalse("Constructor should be inaccessible", constructor.isAccessible());
			constructor.setAccessible(true); // don't try this at home
			Assert.assertEquals("Constructor return type wrong!!", clazz, constructor.newInstance().GetType());
		}
	}

}