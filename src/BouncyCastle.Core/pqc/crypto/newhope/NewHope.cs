using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.digests;
using org.bouncycastle.Port;

namespace org.bouncycastle.pqc.crypto.newhope
{

	
	/// <summary>
	/// This implementation is based heavily on the C reference implementation from https://cryptojedi.org/crypto/index.shtml.
	/// </summary>
	public class NewHope
	{
		private const bool STATISTICAL_TEST = false;

		public const int AGREEMENT_SIZE = 32;
		public const int POLY_SIZE = Params.N;
		public static readonly int SENDA_BYTES = Params.POLY_BYTES + Params.SEED_BYTES;
		public static readonly int SENDB_BYTES = Params.POLY_BYTES + Params.REC_BYTES;

		public static void keygen(SecureRandom rand, byte[] send, short[] sk)
		{
			byte[] seed = new byte[Params.SEED_BYTES];
			rand.nextBytes(seed);

			sha3(seed); // don't expose RNG output

			short[] a = new short[Params.N];
			generateA(a, seed);

			byte[] noiseSeed = new byte[32];
			rand.nextBytes(noiseSeed);

			Poly.getNoise(sk, noiseSeed, 0);
			Poly.toNTT(sk);

			short[] e = new short[Params.N];
			Poly.getNoise(e, noiseSeed, 1);
			Poly.toNTT(e);

			short[] r = new short[Params.N];
			Poly.pointWise(a, sk, r);

			short[] pk = new short[Params.N];
			Poly.add(r, e, pk);

			encodeA(send, pk, seed);
		}

		public static void sharedB(SecureRandom rand, byte[] sharedKey, byte[] send, byte[] received)
		{
			short[] pkA = new short[Params.N];
			byte[] seed = new byte[Params.SEED_BYTES];
			decodeA(pkA, seed, received);

			short[] a = new short[Params.N];
			generateA(a, seed);

			byte[] noiseSeed = new byte[32];
			rand.nextBytes(noiseSeed);

			short[] sp = new short[Params.N];
			Poly.getNoise(sp, noiseSeed, 0);
			Poly.toNTT(sp);

			short[] ep = new short[Params.N];
			Poly.getNoise(ep, noiseSeed, 1);
			Poly.toNTT(ep);

			short[] bp = new short[Params.N];
			Poly.pointWise(a, sp, bp);
			Poly.add(bp, ep, bp);

			short[] v = new short[Params.N];
			Poly.pointWise(pkA, sp, v);
			Poly.fromNTT(v);

			short[] epp = new short[Params.N];
			Poly.getNoise(epp, noiseSeed, 2);
			Poly.add(v, epp, v);

			short[] c = new short[Params.N];
			ErrorCorrection.helpRec(c, v, noiseSeed, 3);

			encodeB(send, bp, c);

			ErrorCorrection.rec(sharedKey, v, c);

			if (!STATISTICAL_TEST)
			{
				sha3(sharedKey);
			}
		}

		public static void sharedA(byte[] sharedKey, short[] sk, byte[] received)
		{
			short[] bp = new short[Params.N];
			short[] c = new short[Params.N];
			decodeB(bp, c, received);

			short[] v = new short[Params.N];
			Poly.pointWise(sk, bp, v);
			Poly.fromNTT(v);

			ErrorCorrection.rec(sharedKey, v, c);

			if (!STATISTICAL_TEST)
			{
				sha3(sharedKey);
			}
		}

		internal static void decodeA(short[] pk, byte[] seed, byte[] r)
		{
			Poly.fromBytes(pk, r);
			JavaSystem.arraycopy(r, Params.POLY_BYTES, seed, 0, Params.SEED_BYTES);
		}

		internal static void decodeB(short[] b, short[] c, byte[] r)
		{
			Poly.fromBytes(b, r);

			for (int i = 0; i < Params.N / 4; ++i)
			{
				int j = 4 * i;
				int ri = r[Params.POLY_BYTES + i] & 0xFF;
				c[j + 0] = (short)(ri & 0x03);
				c[j + 1] = (short)(((int)((uint)ri >> 2)) & 0x03);
				c[j + 2] = (short)(((int)((uint)ri >> 4)) & 0x03);
				c[j + 3] = (short)((int)((uint)ri >> 6));
			}
		}

		internal static void encodeA(byte[] r, short[] pk, byte[] seed)
		{
			Poly.toBytes(r, pk);
			JavaSystem.arraycopy(seed, 0, r, Params.POLY_BYTES, Params.SEED_BYTES);
		}

		internal static void encodeB(byte[] r, short[] b, short[] c)
		{
			Poly.toBytes(r, b);

			for (int i = 0; i < Params.N / 4; ++i)
			{
				int j = 4 * i;
				r[Params.POLY_BYTES + i] = (byte)(c[j] | (c[j + 1] << 2) | (c[j + 2] << 4) | (c[j + 3] << 6));
			}
		}

		internal static void generateA(short[] a, byte[] seed)
		{
			Poly.uniform(a, seed);
		}

		internal static void sha3(byte[] sharedKey)
		{
			SHA3Digest d = new SHA3Digest(256);
			d.update(sharedKey, 0, 32);
			d.doFinal(sharedKey, 0);
		}
	}

}