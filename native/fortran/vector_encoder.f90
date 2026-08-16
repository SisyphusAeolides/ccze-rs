module ccze_vector_encoder
  use, intrinsic :: iso_c_binding
  implicit none

  private
  public :: ccze_compute_state_vector, ccze_update_baseline, ccze_vector_to_binary, &
            ccze_vector_from_binary

  ! State vector dimension - must match VEC_DIM in Vector.agda
  integer, parameter :: vec_dim = 8

  ! Feature indices - must match FeatureIndex in vector.c
  integer, parameter :: idx_length = 1
  integer, parameter :: idx_severity = 2
  integer, parameter :: idx_frequency = 3
  integer, parameter :: idx_timestamp = 4
  integer, parameter :: idx_process_id = 5
  integer, parameter :: idx_entropy = 6
  integer, parameter :: idx_zscore = 7
  integer, parameter :: idx_protocol = 8

  ! Normalization constants
  real(c_double), parameter :: max_length = 1024.0_c_double    ! Max expected line length
  real(c_double), parameter :: max_frequency = 1000.0_c_double  ! Max lines per second
  real(c_double), parameter :: max_pid = 4194304.0_c_double    ! Max PID (2^22)
  real(c_double), parameter :: max_zscore = 10.0_c_double       ! Max z-score before clamping
  real(c_double), parameter :: max_protocol = 4.0_c_double      ! Max protocol phase

  ! Baseline update parameters
  real(c_double), parameter :: baseline_alpha = 0.01_c_double  ! Learning rate for baseline

contains

  ! Compute a state vector from log metrics
  !
  ! Inputs:
  !   length - line length in bytes
  !   severity - severity code (0-5 from Agda Severity)
  !   frequency - lines per second (rolling average)
  !   timestamp - microsecond timestamp (normalized to 0-1 within window)
  !   process_id - PID of the logging process
  !   entropy - error entropy from existing analytics
  !   zscore - z-score from existing analytics
  !   protocol_phase - protocol phase code (0-4 from Idris Phase)
  !
  ! Output:
  !   vector - computed state vector (8 doubles)
  subroutine ccze_compute_state_vector(length, severity, frequency, timestamp, &
                                       process_id, entropy, zscore, protocol_phase, vector) bind(C)
    integer(c_int32_t), value, intent(in) :: length
    integer(c_int32_t), value, intent(in) :: severity
    real(c_double), value, intent(in) :: frequency
    real(c_double), value, intent(in) :: timestamp
    integer(c_int32_t), value, intent(in) :: process_id
    real(c_double), value, intent(in) :: entropy
    real(c_double), value, intent(in) :: zscore
    integer(c_int32_t), value, intent(in) :: protocol_phase
    real(c_double), intent(out) :: vector(vec_dim)

    ! Normalize all features to 0-1 range

    ! Length: normalize to [0, 1]
    vector(idx_length) = min(1.0_c_double, real(length, c_double) / max_length)

    ! Severity: normalize to [0, 1] (0=trace, 5=fatal)
    vector(idx_severity) = min(1.0_c_double, real(severity, c_double) / 5.0_c_double)

    ! Frequency: normalize to [0, 1]
    vector(idx_frequency) = min(1.0_c_double, frequency / max_frequency)

    ! Timestamp: already normalized to [0, 1] within window
    vector(idx_timestamp) = timestamp

    ! Process ID: hash to [0, 1] using simple modulo
    vector(idx_process_id) = mod(real(process_id, c_double), max_pid) / max_pid

    ! Entropy: normalize to [0, 1] (binary entropy max is ~1)
    vector(idx_entropy) = min(1.0_c_double, entropy)

    ! Z-score: clamp and normalize to [0, 1]
    vector(idx_zscore) = min(1.0_c_double, max(0.0_c_double, zscore / max_zscore))

    ! Protocol phase: normalize to [0, 1]
    vector(idx_protocol) = min(1.0_c_double, real(protocol_phase, c_double) / max_protocol)
  end subroutine ccze_compute_state_vector

  ! Update the baseline vector with a new observed vector
  ! Uses exponential moving average: baseline = baseline * (1-alpha) + observed * alpha
  !
  ! Inputs:
  !   baseline - current baseline vector
  !   observed - newly observed vector
  !   alpha - learning rate (0-1)
  !   count - number of vectors used to build baseline (for initialization)
  !
  ! Output:
  !   baseline - updated baseline vector
  subroutine ccze_update_baseline(baseline, observed, alpha, count) bind(C)
    real(c_double), intent(inout) :: baseline(vec_dim)
    real(c_double), intent(in) :: observed(vec_dim)
    real(c_double), value, intent(in) :: alpha
    integer(c_int32_t), value, intent(in) :: count

    integer :: i
    real(c_double) :: inv_alpha

    ! If this is the first vector, just copy it
    if (count <= 1) then
      do i = 1, vec_dim
        baseline(i) = observed(i)
      end do
      return
    end if

    ! Apply exponential moving average
    inv_alpha = 1.0_c_double - alpha
    do i = 1, vec_dim
      baseline(i) = baseline(i) * inv_alpha + observed(i) * alpha
    end do
  end subroutine ccze_update_baseline

  ! Serialize a state vector to binary format for storage
  ! Output is 8 * 8 = 64 bytes (8 doubles)
  !
  ! Input:
  !   vector - state vector to serialize
  !   buffer - output buffer (must be at least 64 bytes)
  subroutine ccze_vector_to_binary(vector, buffer) bind(C)
    real(c_double), intent(in) :: vector(vec_dim)
    integer(c_int8_t), intent(out) :: buffer(64)

    integer :: i, j, offset

    ! Copy each double (8 bytes) into the buffer
    do i = 1, vec_dim
      offset = (i - 1) * 8 + 1
      ! Use transfer to copy bits
      buffer(offset:offset+7) = transfer(vector(i), buffer(offset:offset+7))
    end do
  end subroutine ccze_vector_to_binary

  ! Deserialize a state vector from binary format
  !
  ! Input:
  !   buffer - input buffer (64 bytes)
  !
  ! Output:
  !   vector - deserialized state vector
  subroutine ccze_vector_from_binary(buffer, vector) bind(C)
    integer(c_int8_t), intent(in) :: buffer(64)
    real(c_double), intent(out) :: vector(vec_dim)

    integer :: i, offset

    do i = 1, vec_dim
      offset = (i - 1) * 8 + 1
      vector(i) = transfer(buffer(offset:offset+7), vector(i))
    end do
  end subroutine ccze_vector_from_binary

end module ccze_vector_encoder
