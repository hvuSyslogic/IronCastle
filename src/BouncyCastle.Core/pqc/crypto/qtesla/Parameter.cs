namespace org.bouncycastle.pqc.crypto.qtesla
{
	public sealed class Parameter
	{

		/// <summary>
		/// Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int N_I = 512;

		/// <summary>
		/// Dimension, (Dimension - 1) is the Polynomial Degree for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int N_I_P = 1024;

		/// <summary>
		/// Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int N_III_SIZE = 1024;

		/// <summary>
		/// Dimension, (Dimension - 1) is the Polynomial Degree for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int N_III_SPEED = 1024;

		/// <summary>
		/// Dimension, (Dimension - 1) is the Polynomial Degree for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int N_III_P = 2048;

		/// <summary>
		/// N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int N_LOGARITHM_I = 9;

		/// <summary>
		/// N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int N_LOGARITHM_I_P = 10;

		/// <summary>
		/// N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int N_LOGARITHM_III_SIZE = 10;

		/// <summary>
		/// N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int N_LOGARITHM_III_SPEED = 10;

		/// <summary>
		/// N_LOGARITHM = LOGARITHM (N) / LOGARITHM (2) for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int N_LOGARITHM_III_P = 11;

		/// <summary>
		/// Modulus for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int Q_I = 4205569;

		/// <summary>
		/// Modulus for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int Q_I_P = 485978113;

		/// <summary>
		/// Modulus for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int Q_III_SIZE = 4206593;

		/// <summary>
		/// Modulus for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int Q_III_SPEED = 8404993;

		/// <summary>
		/// Modulus for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int Q_III_P = 1129725953;

		/// <summary>
		/// Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int Q_LOGARITHM_I = 23;

		/// <summary>
		/// Q <= 2 ^ Q_LOGARITHM for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int Q_LOGARITHM_I_P = 29;

		/// <summary>
		/// Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int Q_LOGARITHM_III_SIZE = 23;

		/// <summary>
		/// Q <= 2 ^ Q_LOGARITHM for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int Q_LOGARITHM_III_SPEED = 24;

		/// <summary>
		/// Q <= 2 ^ Q_LOGARITHM for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int Q_LOGARITHM_III_P = 31;

		public const long Q_INVERSE_I = 3098553343L;
		public const long Q_INVERSE_I_P = 3421990911L;
		public const long Q_INVERSE_III_SIZE = 4148178943L;
		public const long Q_INVERSE_III_SPEED = 4034936831L;
		public const long Q_INVERSE_III_P = 861290495L;

		/// <summary>
		/// B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int B_I = 1048575;

		/// <summary>
		/// B Determines the Interval the Randomness is Chosen in During Signing for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int B_I_P = 2097151;

		/// <summary>
		/// B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int B_III_SIZE = 1048575;

		/// <summary>
		/// B Determines the Interval the Randomness is Chosen in During Signing for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int B_III_SPEED = 2097151;

		/// <summary>
		/// B Determines the Interval the Randomness is Chosen in During Signing for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int B_III_P = 8388607;

		/// <summary>
		/// B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int B_BIT_I = 20;

		/// <summary>
		/// B = 2 ^ B_BIT - 1 for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int B_BIT_I_P = 21;

		/// <summary>
		/// B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int B_BIT_III_SIZE = 20;

		/// <summary>
		/// B = 2 ^ B_BIT - 1 for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int B_BIT_III_SPEED = 21;

		/// <summary>
		/// B = 2 ^ B_BIT - 1 for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int B_BIT_III_P = 23;

		public const int S_BIT_I = 10;
		public const int S_BIT_I_P = 8;
		public const int S_BIT_III_SIZE = 8;
		public const int S_BIT_III_SPEED = 9;
		public const int S_BIT_III_P = 8;

		/// <summary>
		/// Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int K_I = 1;

		/// <summary>
		/// Number of Ring-Learning-With-Errors Samples for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int K_I_P = 4;

		/// <summary>
		/// Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int K_III_SIZE = 1;

		/// <summary>
		/// Number of Ring-Learning-With-Errors Samples for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int K_III_SPEED = 1;

		/// <summary>
		/// Number of Ring-Learning-With-Errors Samples for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int K_III_P = 5;

		/// <summary>
		/// Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int H_I = 30;

		/// <summary>
		/// Number of Non-Zero Entries of Output Elements of Encryption for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int H_I_P = 25;

		/// <summary>
		/// Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int H_III_SIZE = 48;

		/// <summary>
		/// Number of Non-Zero Entries of Output Elements of Encryption for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int H_III_SPEED = 48;

		/// <summary>
		/// Number of Non-Zero Entries of Output Elements of Encryption for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int H_III_P = 40;

		/// <summary>
		/// Number of Rounded Bits for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int D_I = 21;

		/// <summary>
		/// Number of Rounded Bits for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int D_I_P = 22;

		/// <summary>
		/// Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int D_III_SIZE = 21;

		/// <summary>
		/// Number of Rounded Bits for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int D_III_SPEED = 22;

		/// <summary>
		/// Number of Rounded Bits for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int D_III_P = 24;

		/// <summary>
		/// Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_I = 1586;

		/// <summary>
		/// Bound in Checking Error Polynomial for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_I_P = 554;

		/// <summary>
		/// Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_III_SIZE = 910;

		/// <summary>
		/// Bound in Checking Error Polynomial for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_III_SPEED = 1147;

		/// <summary>
		/// Bound in Checking Error Polynomial for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int KEY_GENERATOR_BOUND_E_III_P = 901;

		public const int REJECTION_I = KEY_GENERATOR_BOUND_E_I;
		public const int REJECTION_I_P = KEY_GENERATOR_BOUND_E_I_P;
		public const int REJECTION_III_SIZE = KEY_GENERATOR_BOUND_E_III_SIZE;
		public const int REJECTION_III_SPEED = KEY_GENERATOR_BOUND_E_III_SPEED;
		public const int REJECTION_III_P = KEY_GENERATOR_BOUND_E_III_P;

		/// <summary>
		/// Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_I = 1586;

		/// <summary>
		/// Bound in Checking Secret Polynomial for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_I_P = 554;

		/// <summary>
		/// Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_III_SIZE = 910;

		/// <summary>
		/// Bound in Checking Secret Polynomial for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_III_SPEED = 1233;

		/// <summary>
		/// Bound in Checking Secret Polynomial for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int KEY_GENERATOR_BOUND_S_III_P = 901;

		public const int U_I = KEY_GENERATOR_BOUND_S_I;
		public const int U_I_P = KEY_GENERATOR_BOUND_S_I_P;
		public const int U_III_SIZE = KEY_GENERATOR_BOUND_S_III_SIZE;
		public const int U_III_SPEED = KEY_GENERATOR_BOUND_S_III_SPEED;
		public const int U_III_P = KEY_GENERATOR_BOUND_S_III_P;

		/// <summary>
		/// Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-1
		/// </summary>
		public const double SIGMA_I = 22.93;

		/// <summary>
		/// Standard Deviation of Centered Discrete Gaussian Distribution for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const double SIGMA_I_P = 8.5;

		/// <summary>
		/// Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const double SIGMA_III_SIZE = 7.64;

		/// <summary>
		/// Standard Deviation of Centered Discrete Gaussian Distribution for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const double SIGMA_III_SPEED = 10.2;

		/// <summary>
		/// Standard Deviation of Centered Discrete Gaussian Distribution for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const double SIGMA_III_P = 8.5;

		public const double SIGMA_E_I = SIGMA_I;
		public const double SIGMA_E_I_P = SIGMA_I_P;
		public const double SIGMA_E_III_SIZE = SIGMA_III_SIZE;
		public const double SIGMA_E_III_SPEED = SIGMA_III_SPEED;
		public const double SIGMA_E_III_P = SIGMA_III_P;

		/// <summary>
		/// XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-1
		/// </summary>
		public const double XI_I = 27;

		/// <summary>
		/// XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const double XI_I_P = 10;

		/// <summary>
		/// XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const double XI_III_SIZE = 9;

		/// <summary>
		/// XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Heuristic qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const double XI_III_SPEED = 12;

		/// <summary>
		/// XI = SIGMA * SQUARE_ROOT (2 * LOGARITHM (2) / LOGARITHM (e)) for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const double XI_III_P = 10;

		public const int BARRETT_MULTIPLICATION_I = 1021;
		public const int BARRETT_MULTIPLICATION_I_P = 1;
		public const int BARRETT_MULTIPLICATION_III_SIZE = 1021;
		public const int BARRETT_MULTIPLICATION_III_SPEED = 511;
		public const int BARRETT_MULTIPLICATION_III_P = 15;

		public const int BARRETT_DIVISION_I = 32;
		public const int BARRETT_DIVISION_I_P = 29;
		public const int BARRETT_DIVISION_III_SIZE = 32;
		public const int BARRETT_DIVISION_III_SPEED = 32;
		public const int BARRETT_DIVISION_III_P = 34;

		/// <summary>
		/// The Number of Blocks Requested in the First Extendable-Output Function Call
		/// for Heuristic qTESLA Security Category-1
		/// </summary>
		public const int GENERATOR_A_I = 19;

		/// <summary>
		/// The Number of Blocks Requested in the First Extendable-Output Function Call
		/// for Provably-Secure qTESLA Security Category-1
		/// </summary>
		public const int GENERATOR_A_I_P = 108;

		/// <summary>
		/// The Number of Blocks Requested in the First Extendable-Output Function Call
		/// for Provably-Secure qTESLA Security Category-3 (Option for Size)
		/// </summary>
		public const int GENERATOR_A_III_SIZE = 38;

		/// <summary>
		/// The Number of Blocks Requested in the First Extendable-Output Function Call
		/// for Provably-Secure qTESLA Security Category-3 (Option for Speed)
		/// </summary>
		public const int GENERATOR_A_III_SPEED = 38;

		/// <summary>
		/// The Number of Blocks Requested in the First Extendable-Output Function Call
		/// for Provably-Secure qTESLA Security Category-3
		/// </summary>
		public const int GENERATOR_A_III_P = 180;

		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_I = 113307;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_I_P = 472064468;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SIZE = 1217638;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_SPEED = 237839;
		public const int INVERSE_NUMBER_THEORETIC_TRANSFORM_III_P = 851423148;

		public const int R_I = 1081347;
		public const int R_III_SIZE = 35843;
		public const int R_III_SPEED = 15873;

	}
}