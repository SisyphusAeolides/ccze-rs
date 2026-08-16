module ccze_analytics
  use, intrinsic :: iso_c_binding
  implicit none
contains
  subroutine ccze_analyze_metrics(lengths, errors, count, threshold, zscore, entropy, anomaly) bind(C)
    integer(c_int32_t), intent(in) :: lengths(*)
    integer(c_int32_t), intent(in) :: errors(*)
    integer(c_size_t), value, intent(in) :: count
    real(c_double), value, intent(in) :: threshold
    real(c_double), intent(out) :: zscore
    real(c_double), intent(out) :: entropy
    integer(c_int32_t), intent(out) :: anomaly
    real(c_double) :: mean, variance, delta, error_rate, probability
    integer(c_size_t) :: i

    if (count == 0) then
      zscore = 0.0_c_double
      entropy = 0.0_c_double
      anomaly = 0_c_int32_t
      return
    end if

    mean = 0.0_c_double
    error_rate = 0.0_c_double
    do i = 1, count
      mean = mean + real(lengths(i), c_double)
      error_rate = error_rate + real(errors(i), c_double)
    end do
    mean = mean / real(count, c_double)
    error_rate = error_rate / real(count, c_double)

    variance = 0.0_c_double
    do i = 1, count
      delta = real(lengths(i), c_double) - mean
      variance = variance + delta * delta
    end do
    variance = variance / real(count, c_double)

    if (variance > 0.0_c_double) then
      zscore = abs(real(lengths(count), c_double) - mean) / sqrt(variance)
    else
      zscore = 0.0_c_double
    end if

    entropy = 0.0_c_double
    if (error_rate > 0.0_c_double) then
      entropy = entropy - error_rate * (log(error_rate) / log(2.0_c_double))
    end if
    probability = 1.0_c_double - error_rate
    if (probability > 0.0_c_double) then
      entropy = entropy - probability * (log(probability) / log(2.0_c_double))
    end if

    if (zscore >= threshold .or. error_rate >= 0.5_c_double) then
      anomaly = 1_c_int32_t
    else
      anomaly = 0_c_int32_t
    end if
  end subroutine ccze_analyze_metrics
end module ccze_analytics
