﻿using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.digests
{

	/*  The BLAKE2 cryptographic hash function was designed by Jean-
	 Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn, and Christian
	 Winnerlein.
	   
	 Reference Implementation and Description can be found at: https://blake2.net/      
	 Internet Draft: https://tools.ietf.org/html/draft-saarinen-blake2-02
	
	 This implementation does not support the Tree Hashing Mode. 
	 
	   For unkeyed hashing, developers adapting BLAKE2 to ASN.1 - based
	   message formats SHOULD use the OID tree at x = 1.3.6.1.4.1.1722.12.2.
	
	         Algorithm     | Target | Collision | Hash | Hash ASN.1 |
	            Identifier |  Arch  |  Security |  nn  | OID Suffix |
	        ---------------+--------+-----------+------+------------+
	         id-blake2b160 | 64-bit |   2**80   |  20  |   x.1.20   |
	         id-blake2b256 | 64-bit |   2**128  |  32  |   x.1.32   |
	         id-blake2b384 | 64-bit |   2**192  |  48  |   x.1.48   |
	         id-blake2b512 | 64-bit |   2**256  |  64  |   x.1.64   |
	        ---------------+--------+-----------+------+------------+
	 */

		

	/// <summary>
	/// Implementation of the cryptographic hash function Blakbe2b.
	/// <para>
	/// Blake2b offers a built-in keying mechanism to be used directly
	/// for authentication ("Prefix-MAC") rather than a HMAC construction.
	/// </para>
	/// <para>
	/// Blake2b offers a built-in support for a salt for randomized hashing
	/// and a personal string for defining a unique hash function for each application.
	/// </para>
	/// <para>
	/// BLAKE2b is optimized for 64-bit platforms and produces digests of any size
	/// between 1 and 64 bytes.
	/// </para>
	/// </summary>
	public class Blake2bDigest : ExtendedDigest
	{
		// Blake2b Initialization Vector:
		private static readonly long[] blake2b_IV = new long[] {0x6a09e667f3bcc908L, unchecked((long)0xbb67ae8584caa73bL), 0x3c6ef372fe94f82bL, unchecked((long)0xa54ff53a5f1d36f1L), 0x510e527fade682d1L, unchecked((long)0x9b05688c2b3e6c1fL), 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L};

		// Message word permutations:
		private static readonly byte[][] blake2b_sigma = new byte[][]
		{
			new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			new byte[] {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
			new byte[] {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
			new byte[] {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
			new byte[] {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
			new byte[] {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
			new byte[] {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
			new byte[] {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
			new byte[] {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
			new byte[] {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
			new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			new byte[] {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
		};

		private static int ROUNDS = 12; // to use for Catenas H'
		private const int BLOCK_LENGTH_BYTES = 128; // bytes

		// General parameters:
		private int digestLength = 64; // 1- 64 bytes
		private int keyLength = 0; // 0 - 64 bytes for keyed hashing for MAC
		private byte[] salt = null; // new byte[16];
		private byte[] personalization = null; // new byte[16];

		// the key
		private byte[] key = null;

		// Tree hashing parameters:
		// Because this class does not implement the Tree Hashing Mode,
		// these parameters can be treated as constants (see init() function)
		/*
		 * private int fanout = 1; // 0-255 private int depth = 1; // 1 - 255
		 * private int leafLength= 0; private long nodeOffset = 0L; private int
		 * nodeDepth = 0; private int innerHashLength = 0;
		 */

		// whenever this buffer overflows, it will be processed
		// in the compress() function.
		// For performance issues, long messages will not use this buffer.
		private byte[] buffer = null; // new byte[BLOCK_LENGTH_BYTES];
		// Position of last inserted byte:
		private int bufferPos = 0; // a value from 0 up to 128

		private long[] internalState = new long[16]; // In the Blake2b paper it is
		// called: v
		private long[] chainValue = null; // state vector, in the Blake2b paper it
		// is called: h

		private long t0 = 0L; // holds last significant bits, counter (counts bytes)
		private long t1 = 0L; // counter: Length up to 2^128 are supported
		private long f0 = 0L; // finalization flag, for last block: ~0L

		// For Tree Hashing Mode, not used here:
		// private long f1 = 0L; // finalization flag, for last node: ~0L

		public Blake2bDigest() : this(512)
		{
		}

		public Blake2bDigest(Blake2bDigest digest)
		{
			this.bufferPos = digest.bufferPos;
			this.buffer = Arrays.clone(digest.buffer);
			this.keyLength = digest.keyLength;
			this.key = Arrays.clone(digest.key);
			this.digestLength = digest.digestLength;
			this.chainValue = Arrays.clone(digest.chainValue);
			this.personalization = Arrays.clone(digest.personalization);
			this.salt = Arrays.clone(digest.salt);
			this.t0 = digest.t0;
			this.t1 = digest.t1;
			this.f0 = digest.f0;
		}

		/// <summary>
		/// Basic sized constructor - size in bits.
		/// </summary>
		/// <param name="digestSize"> size of the digest in bits </param>
		public Blake2bDigest(int digestSize)
		{
			if (digestSize < 8 || digestSize > 512 || digestSize % 8 != 0)
			{
				throw new IllegalArgumentException("BLAKE2b digest bit length must be a multiple of 8 and not greater than 512");
			}

			buffer = new byte[BLOCK_LENGTH_BYTES];
			keyLength = 0;
			this.digestLength = digestSize / 8;
			init();
		}

		/// <summary>
		/// Blake2b for authentication ("Prefix-MAC mode").
		/// After calling the doFinal() method, the key will
		/// remain to be used for further computations of
		/// this instance.
		/// The key can be overwritten using the clearKey() method.
		/// </summary>
		/// <param name="key"> A key up to 64 bytes or null </param>
		public Blake2bDigest(byte[] key)
		{
			buffer = new byte[BLOCK_LENGTH_BYTES];
			if (key != null)
			{
				this.key = new byte[key.Length];
				JavaSystem.arraycopy(key, 0, this.key, 0, key.Length);

				if (key.Length > 64)
				{
					throw new IllegalArgumentException("Keys > 64 are not supported");
				}
				keyLength = key.Length;
				JavaSystem.arraycopy(key, 0, buffer, 0, key.Length);
				bufferPos = BLOCK_LENGTH_BYTES; // zero padding
			}
			digestLength = 64;
			init();
		}

		/// <summary>
		/// Blake2b with key, required digest length (in bytes), salt and personalization.
		/// After calling the doFinal() method, the key, the salt and the personal string
		/// will remain and might be used for further computations with this instance.
		/// The key can be overwritten using the clearKey() method, the salt (pepper)
		/// can be overwritten using the clearSalt() method.
		/// </summary>
		/// <param name="key">             A key up to 64 bytes or null </param>
		/// <param name="digestLength">    from 1 up to 64 bytes </param>
		/// <param name="salt">            16 bytes or null </param>
		/// <param name="personalization"> 16 bytes or null </param>
		public Blake2bDigest(byte[] key, int digestLength, byte[] salt, byte[] personalization)
		{

			buffer = new byte[BLOCK_LENGTH_BYTES];
			if (digestLength < 1 || digestLength > 64)
			{
				throw new IllegalArgumentException("Invalid digest length (required: 1 - 64)");
			}
			this.digestLength = digestLength;
			if (salt != null)
			{
				if (salt.Length != 16)
				{
					throw new IllegalArgumentException("salt length must be exactly 16 bytes");
				}
				this.salt = new byte[16];
				JavaSystem.arraycopy(salt, 0, this.salt, 0, salt.Length);
			}
			if (personalization != null)
			{
				if (personalization.Length != 16)
				{
					throw new IllegalArgumentException("personalization length must be exactly 16 bytes");
				}
				this.personalization = new byte[16];
				JavaSystem.arraycopy(personalization, 0, this.personalization, 0, personalization.Length);
			}
			if (key != null)
			{
				this.key = new byte[key.Length];
				JavaSystem.arraycopy(key, 0, this.key, 0, key.Length);

				if (key.Length > 64)
				{
					throw new IllegalArgumentException("Keys > 64 are not supported");
				}
				keyLength = key.Length;
				JavaSystem.arraycopy(key, 0, buffer, 0, key.Length);
				bufferPos = BLOCK_LENGTH_BYTES; // zero padding
			}
			init();
		}

		// initialize chainValue
		private void init()
		{
			if (chainValue == null)
			{
				chainValue = new long[8];

				chainValue[0] = blake2b_IV[0] ^ (digestLength | (keyLength << 8) | 0x1010000);
				// 0x1010000 = ((fanout << 16) | (depth << 24) | (leafLength <<
				// 32));
				// with fanout = 1; depth = 0; leafLength = 0;
				chainValue[1] = blake2b_IV[1]; // ^ nodeOffset; with nodeOffset = 0;
				chainValue[2] = blake2b_IV[2]; // ^ ( nodeDepth | (innerHashLength <<
				// 8) );
				// with nodeDepth = 0; innerHashLength = 0;

				chainValue[3] = blake2b_IV[3];

				chainValue[4] = blake2b_IV[4];
				chainValue[5] = blake2b_IV[5];
				if (salt != null)
				{
					chainValue[4] ^= Pack.littleEndianToLong(salt, 0);
					chainValue[5] ^= Pack.littleEndianToLong(salt, 8);
				}

				chainValue[6] = blake2b_IV[6];
				chainValue[7] = blake2b_IV[7];
				if (personalization != null)
				{
					chainValue[6] ^= Pack.littleEndianToLong(personalization, 0);
					chainValue[7] ^= Pack.littleEndianToLong(personalization, 8);
				}
			}
		}

		private void initializeInternalState()
		{
			// initialize v:
			JavaSystem.arraycopy(chainValue, 0, internalState, 0, chainValue.Length);
			JavaSystem.arraycopy(blake2b_IV, 0, internalState, chainValue.Length, 4);
			internalState[12] = t0 ^ blake2b_IV[4];
			internalState[13] = t1 ^ blake2b_IV[5];
			internalState[14] = f0 ^ blake2b_IV[6];
			internalState[15] = blake2b_IV[7]; // ^ f1 with f1 = 0
		}

		/// <summary>
		/// update the message digest with a single byte.
		/// </summary>
		/// <param name="b"> the input byte to be entered. </param>
		public virtual void update(byte b)
		{
			int remainingLength = 0; // left bytes of buffer

			// process the buffer if full else add to buffer:
			remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
			if (remainingLength == 0)
			{ // full buffer
				t0 += BLOCK_LENGTH_BYTES;
				if (t0 == 0)
				{ // if message > 2^64
					t1++;
				}
				compress(buffer, 0);
				Arrays.fill(buffer, 0); // clear buffer
				buffer[0] = b;
				bufferPos = 1;
			}
			else
			{
				buffer[bufferPos] = b;
				bufferPos++;
				return;
			}
		}

		/// <summary>
		/// update the message digest with a block of bytes.
		/// </summary>
		/// <param name="message"> the byte array containing the data. </param>
		/// <param name="offset">  the offset into the byte array where the data starts. </param>
		/// <param name="len">     the length of the data. </param>
		public virtual void update(byte[] message, int offset, int len)
		{

			if (message == null || len == 0)
			{
				return;
			}

			int remainingLength = 0; // left bytes of buffer

			if (bufferPos != 0)
			{ // commenced, incomplete buffer

				// complete the buffer:
				remainingLength = BLOCK_LENGTH_BYTES - bufferPos;
				if (remainingLength < len)
				{ // full buffer + at least 1 byte
					JavaSystem.arraycopy(message, offset, buffer, bufferPos, remainingLength);
					t0 += BLOCK_LENGTH_BYTES;
					if (t0 == 0)
					{ // if message > 2^64
						t1++;
					}
					compress(buffer, 0);
					bufferPos = 0;
					Arrays.fill(buffer, 0); // clear buffer
				}
				else
				{
					JavaSystem.arraycopy(message, offset, buffer, bufferPos, len);
					bufferPos += len;
					return;
				}
			}

			// process blocks except last block (also if last block is full)
			int messagePos;
			int blockWiseLastPos = offset + len - BLOCK_LENGTH_BYTES;
			for (messagePos = offset + remainingLength; messagePos < blockWiseLastPos; messagePos += BLOCK_LENGTH_BYTES)
			{ // block wise 128 bytes
				// without buffer:
				t0 += BLOCK_LENGTH_BYTES;
				if (t0 == 0)
				{
					t1++;
				}
				compress(message, messagePos);
			}

			// fill the buffer with left bytes, this might be a full block
			JavaSystem.arraycopy(message, messagePos, buffer, 0, offset + len - messagePos);
			bufferPos += offset + len - messagePos;
		}

		/// <summary>
		/// close the digest, producing the final digest value. The doFinal
		/// call leaves the digest reset.
		/// Key, salt and personal string remain.
		/// </summary>
		/// <param name="out">       the array the digest is to be copied into. </param>
		/// <param name="outOffset"> the offset into the out array the digest is to start at. </param>
		public virtual int doFinal(byte[] @out, int outOffset)
		{

			f0 = unchecked((long)0xFFFFFFFFFFFFFFFFL);
			t0 += bufferPos;
			if (bufferPos > 0 && t0 == 0)
			{
				t1++;
			}
			compress(buffer, 0);
			Arrays.fill(buffer, 0); // Holds eventually the key if input is null
			Arrays.fill(internalState, 0L);

			for (int i = 0; i < chainValue.Length && (i * 8 < digestLength); i++)
			{
				byte[] bytes = Pack.longToLittleEndian(chainValue[i]);

				if (i * 8 < digestLength - 8)
				{
					JavaSystem.arraycopy(bytes, 0, @out, outOffset + i * 8, 8);
				}
				else
				{
					JavaSystem.arraycopy(bytes, 0, @out, outOffset + i * 8, digestLength - (i * 8));
				}
			}

			Arrays.fill(chainValue, 0L);

			reset();

			return digestLength;
		}

		/// <summary>
		/// Reset the digest back to it's initial state.
		/// The key, the salt and the personal string will
		/// remain for further computations.
		/// </summary>
		public virtual void reset()
		{
			bufferPos = 0;
			f0 = 0L;
			t0 = 0L;
			t1 = 0L;
			chainValue = null;
			Arrays.fill(buffer, 0);
			if (key != null)
			{
				JavaSystem.arraycopy(key, 0, buffer, 0, key.Length);
				bufferPos = BLOCK_LENGTH_BYTES; // zero padding
			}
			init();
		}

		private void compress(byte[] message, int messagePos)
		{

			initializeInternalState();

			long[] m = new long[16];
			for (int j = 0; j < 16; j++)
			{
				m[j] = Pack.littleEndianToLong(message, messagePos + j * 8);
			}

			for (int round = 0; round < ROUNDS; round++)
			{

				// G apply to columns of internalState:m[blake2b_sigma[round][2 *
				// blockPos]] /+1
				G(m[blake2b_sigma[round][0]], m[blake2b_sigma[round][1]], 0, 4, 8, 12);
				G(m[blake2b_sigma[round][2]], m[blake2b_sigma[round][3]], 1, 5, 9, 13);
				G(m[blake2b_sigma[round][4]], m[blake2b_sigma[round][5]], 2, 6, 10, 14);
				G(m[blake2b_sigma[round][6]], m[blake2b_sigma[round][7]], 3, 7, 11, 15);
				// G apply to diagonals of internalState:
				G(m[blake2b_sigma[round][8]], m[blake2b_sigma[round][9]], 0, 5, 10, 15);
				G(m[blake2b_sigma[round][10]], m[blake2b_sigma[round][11]], 1, 6, 11, 12);
				G(m[blake2b_sigma[round][12]], m[blake2b_sigma[round][13]], 2, 7, 8, 13);
				G(m[blake2b_sigma[round][14]], m[blake2b_sigma[round][15]], 3, 4, 9, 14);
			}

			// update chain values:
			for (int offset = 0; offset < chainValue.Length; offset++)
			{
				chainValue[offset] = chainValue[offset] ^ internalState[offset] ^ internalState[offset + 8];
			}
		}

		private void G(long m1, long m2, int posA, int posB, int posC, int posD)
		{

			internalState[posA] = internalState[posA] + internalState[posB] + m1;
			internalState[posD] = rotr64(internalState[posD] ^ internalState[posA], 32);
			internalState[posC] = internalState[posC] + internalState[posD];
			internalState[posB] = rotr64(internalState[posB] ^ internalState[posC], 24); // replaces 25 of BLAKE
			internalState[posA] = internalState[posA] + internalState[posB] + m2;
			internalState[posD] = rotr64(internalState[posD] ^ internalState[posA], 16);
			internalState[posC] = internalState[posC] + internalState[posD];
			internalState[posB] = rotr64(internalState[posB] ^ internalState[posC], 63); // replaces 11 of BLAKE
		}

		private static long rotr64(long x, int rot)
		{
			return (long)((ulong)x >> rot) | (x << (64 - rot));
		}

		/// <summary>
		/// return the algorithm name
		/// </summary>
		/// <returns> the algorithm name </returns>
		public virtual string getAlgorithmName()
		{
			return "BLAKE2b";
		}

		/// <summary>
		/// return the size, in bytes, of the digest produced by this message digest.
		/// </summary>
		/// <returns> the size, in bytes, of the digest produced by this message digest. </returns>
		public virtual int getDigestSize()
		{
			return digestLength;
		}

		/// <summary>
		/// Return the size in bytes of the internal buffer the digest applies it's compression
		/// function to.
		/// </summary>
		/// <returns> byte length of the digests internal buffer. </returns>
		public virtual int getByteLength()
		{
			return BLOCK_LENGTH_BYTES;
		}

		/// <summary>
		/// Overwrite the key
		/// if it is no longer used (zeroization)
		/// </summary>
		public virtual void clearKey()
		{
			if (key != null)
			{
				Arrays.fill(key, 0);
				Arrays.fill(buffer, 0);
			}
		}

		/// <summary>
		/// Overwrite the salt (pepper) if it
		/// is secret and no longer used (zeroization)
		/// </summary>
		public virtual void clearSalt()
		{
			if (salt != null)
			{
				Arrays.fill(salt, 0);
			}
		}
	}

}