﻿using org.bouncycastle.asn1.rosstandart;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.misc;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.iso;
using org.bouncycastle.asn1.ua;

namespace org.bouncycastle.jce.provider.test
{

	using ISOIECObjectIdentifiers = org.bouncycastle.asn1.iso.ISOIECObjectIdentifiers;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using UAObjectIdentifiers = org.bouncycastle.asn1.ua.UAObjectIdentifiers;
	using Hex = org.bouncycastle.util.encoders.Hex;
	using SimpleTest = org.bouncycastle.util.test.SimpleTest;

	public class DigestTest : SimpleTest
	{
		internal const string provider = "BC";

		private static string[][] abcVectors = new string[][]
		{
			new string[] {"MD2", "da853b0d3f88d99b30283a69e6ded6bb"},
			new string[] {"MD4", "a448017aaf21d8525fc10ae87aa6729d"},
			new string[] {"MD5", "900150983cd24fb0d6963f7d28e17f72"},
			new string[] {"SHA-1", "a9993e364706816aba3e25717850c26c9cd0d89d"},
			new string[] {"SHA-224", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
			new string[] {"SHA-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
			new string[] {"SHA-384", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
			new string[] {"SHA-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
			new string[] {"SHA-512/224", "4634270F707B6A54DAAE7530460842E20E37ED265CEEE9A43E8924AA"},
			new string[] {"SHA-512/256", "53048E2681941EF99B2E29B76B4C7DABE4C2D0C634FC6D46E0E2F13107E7AF23"},
			new string[] {"RIPEMD128", "c14a12199c66e4ba84636b0f69144c77"},
			new string[] {TeleTrusTObjectIdentifiers_Fields.ripemd128.getId(), "c14a12199c66e4ba84636b0f69144c77"},
			new string[] {"RIPEMD160", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
			new string[] {TeleTrusTObjectIdentifiers_Fields.ripemd160.getId(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"},
			new string[] {"RIPEMD256", "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"},
			new string[] {TeleTrusTObjectIdentifiers_Fields.ripemd256.getId(), "afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65"},
			new string[] {"RIPEMD320", "de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d"},
			new string[] {"Tiger", "2AAB1484E8C158F2BFB8C5FF41B57A525129131C957B5F93"},
			new string[] {"GOST3411", "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c"},
			new string[] {"WHIRLPOOL", "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"},
			new string[] {ISOIECObjectIdentifiers_Fields.whirlpool.getId(), "4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5"},
			new string[] {"SM3", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
			new string[] {"SHA3-224", "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
			new string[] {"SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
			new string[] {"SHA3-384", "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
			new string[] {"SHA3-512", "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
			new string[] {NISTObjectIdentifiers_Fields.id_sha3_224.getId(), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf"},
			new string[] {NISTObjectIdentifiers_Fields.id_sha3_256.getId(), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
			new string[] {NISTObjectIdentifiers_Fields.id_sha3_384.getId(), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
			new string[] {NISTObjectIdentifiers_Fields.id_sha3_512.getId(), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
			new string[] {"KECCAK-224", "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8"},
			new string[] {"KECCAK-256", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"},
			new string[] {"KECCAK-288", "20ff13d217d5789fa7fc9e0e9a2ee627363ec28171d0b6c52bbd2f240554dbc94289f4d6"},
			new string[] {"KECCAK-384", "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e"},
			new string[] {"KECCAK-512", "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96"},
			new string[] {"BLAKE2B-160", "384264f676f39536840523f284921cdc68b6846b"},
			new string[] {"BLAKE2B-256", "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
			new string[] {"BLAKE2B-384", "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"},
			new string[] {"BLAKE2B-512", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2b160.getId(), "384264f676f39536840523f284921cdc68b6846b"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2b256.getId(), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2b384.getId(), "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2b512.getId(), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"},
			new string[] {"BLAKE2S-128", "aa4938119b1dc7b87cbad0ffd200d0ae"},
			new string[] {"BLAKE2S-160", "5ae3b99be29b01834c3b508521ede60438f8de17"},
			new string[] {"BLAKE2S-224", "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55"},
			new string[] {"BLAKE2S-256", "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2s128.getId(), "aa4938119b1dc7b87cbad0ffd200d0ae"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2s160.getId(), "5ae3b99be29b01834c3b508521ede60438f8de17"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2s224.getId(), "0b033fc226df7abde29f67a05d3dc62cf271ef3dfea4d387407fbd55"},
			new string[] {MiscObjectIdentifiers_Fields.id_blake2s256.getId(), "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"},
			new string[] {"GOST3411-2012-256", "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481"},
			new string[] {RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_256.getId(), "4e2919cf137ed41ec4fb6270c61826cc4fffb660341e0af3688cd0626d23b481"},
			new string[] {"GOST3411-2012-512", "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728"},
			new string[] {RosstandartObjectIdentifiers_Fields.id_tc26_gost_3411_12_512.getId(), "28156e28317da7c98f4fe2bed6b542d0dab85bb224445fcedaf75d46e26d7eb8d5997f3e0915dd6b7f0aab08d9c8beb0d8c64bae2ab8b3c8c6bc53b3bf0db728"},
			new string[] {"DSTU7564-256", "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"},
			new string[] {UAObjectIdentifiers_Fields.dstu7564digest_256.getId(), "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04"},
			new string[] {"DSTU7564-384", "72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88"},
			new string[] {UAObjectIdentifiers_Fields.dstu7564digest_384.getId(), "72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88"},
			new string[] {"DSTU7564-512", "9e5be7daf7b68b49d2ecbd04c7a5b3af72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88"},
			new string[] {UAObjectIdentifiers_Fields.dstu7564digest_512.getId(), "9e5be7daf7b68b49d2ecbd04c7a5b3af72945012b0820c3132846ddc90da511f80bb7b70abd0cb1ab8df785d600c187b9d0ac567e8b6f76fde8a0b417a2ebf88"}
		};

		public override string getName()
		{
			return "Digest";
		}

		public virtual void test(string algorithm)
		{
			byte[] message = "hello world".GetBytes();

			MessageDigest digest = MessageDigest.getInstance(algorithm, provider);

			byte[] result = digest.digest(message);
			byte[] result2 = digest.digest(message);

			// test one digest the same message with the same instance
			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 1 not equal");
			}

			// test two, single byte updates
			for (int i = 0; i < message.Length; i++)
			{
				digest.update(message[i]);
			}
			result2 = digest.digest();

			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 2 not equal");
			}

			// test three, two half updates
			digest.update(message, 0, message.Length / 2);
			digest.update(message, message.Length / 2, message.Length - message.Length / 2);
			result2 = digest.digest();

			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 3 not equal");
			}

			// test four, clone test
			digest.update(message, 0, message.Length / 2);
			MessageDigest d = (MessageDigest)digest.clone();
			digest.update(message, message.Length / 2, message.Length - message.Length / 2);
			result2 = digest.digest();

			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 4(a) not equal");
			}

			d.update(message, message.Length / 2, message.Length - message.Length / 2);
			result2 = d.digest();

			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 4(b) not equal");
			}

			// test five, check reset() method
			digest.update(message, 0, message.Length / 2);
			digest.reset();
			digest.update(message, 0, message.Length / 2);
			digest.update(message, message.Length / 2, message.Length - message.Length / 2);
			result2 = digest.digest();

			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 5 not equal");
			}

			// test six, check reset() method with longer message
			digest.update(message);
			digest.update(message);
			digest.reset();

			result2 = digest.digest(message);

			if (!MessageDigest.isEqual(result, result2))
			{
				fail("Result object 6 not equal");
			}
		}

		/// <summary>
		/// Test the hash against a standard value for the string "abc"
		/// </summary>
		/// <param name="algorithm"> algorithm to test </param>
		/// <param name="hash"> expected value </param>
		/// <returns> the test result. </returns>
		public virtual void abcTest(string algorithm, string hash)
		{
			byte[] abc = new byte[] {(byte)0x61, (byte)0x62, (byte)0x63};

			MessageDigest digest = MessageDigest.getInstance(algorithm, provider);

			byte[] result = digest.digest(abc);

			if (!MessageDigest.isEqual(result, Hex.decode(hash)))
			{
				JavaSystem.err.println(Hex.toHexString(result));
				fail("abc result not equal for " + algorithm);
			}
		}

		public override void performTest()
		{
			for (int i = 0; i != abcVectors.Length; i++)
			{
				test(abcVectors[i][0]);

				abcTest(abcVectors[i][0], abcVectors[i][1]);
			}
		}

		public static void Main(string[] args)
		{
			Security.addProvider(new BouncyCastleProvider());

			runTest(new DigestTest());
		}
	}


}