using BouncyCastle.Core.Port.java.util;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.signers
{

	
	public class ISOTrailers
	{
		private static readonly Map<string, int> trailerMap;

		public const int TRAILER_IMPLICIT = 0xBC;

		public const int TRAILER_RIPEMD160 = 0x31CC;
		public const int TRAILER_RIPEMD128 = 0x32CC;
		public const int TRAILER_SHA1 = 0x33CC;
		public const int TRAILER_SHA256 = 0x34CC;
		public const int TRAILER_SHA512 = 0x35CC;
		public const int TRAILER_SHA384 = 0x36CC;
		public const int TRAILER_WHIRLPOOL = 0x37CC;
		public const int TRAILER_SHA224 = 0x38CC;
		public const int TRAILER_SHA512_224 = 0x39CC;
		public const int TRAILER_SHA512_256 = 0x3aCC;

		static ISOTrailers()
		{
			Map<string, int> trailers = new HashMap<string, int>();

			trailers.put("RIPEMD128", Integers.valueOf(TRAILER_RIPEMD128));
			trailers.put("RIPEMD160", Integers.valueOf(TRAILER_RIPEMD160));

			trailers.put("SHA-1", Integers.valueOf(TRAILER_SHA1));
			trailers.put("SHA-224", Integers.valueOf(TRAILER_SHA224));
			trailers.put("SHA-256", Integers.valueOf(TRAILER_SHA256));
			trailers.put("SHA-384", Integers.valueOf(TRAILER_SHA384));
			trailers.put("SHA-512", Integers.valueOf(TRAILER_SHA512));
			trailers.put("SHA-512/224", Integers.valueOf(TRAILER_SHA512_224));
			trailers.put("SHA-512/256", Integers.valueOf(TRAILER_SHA512_256));

			trailers.put("Whirlpool", Integers.valueOf(TRAILER_WHIRLPOOL));

			trailerMap = Collections.unmodifiableMap(trailers);
		}

		public static int? getTrailer(Digest digest)
		{
			return trailerMap.get(digest.getAlgorithmName()); // JDK 1.4 compatibility
		}

		public static bool noTrailerAvailable(Digest digest)
		{
			return !trailerMap.containsKey(digest.getAlgorithmName());
		}
	}

}