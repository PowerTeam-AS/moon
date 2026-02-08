#!/usr/bin/env bash

# U-20 : /etc/(x)inetd.conf 파일 소유자 및 권한 설정
# /etc/(x)inetd.conf 파일 권한 적절성 여부 점검

set -u

CHECK_ID="U-20"
# 타겟 아래에 작성 (여러 파일)

# ==== 로그 저장 경로 설정 ==== # TODO : 루트 변경 시 수정
LOG_DIR="/home/rockylinux/results"
LOG_FILE="$LOG_DIR/$CHECK_ID.log"
mkdir -p "$LOG_DIR"

# ==== 점검 걸린 시간 기록
start_ms() {
  if date +%s%3N >/dev/null 2>&1; then
    date +%s%3N
  else
    echo "$(( $(date +%s) * 1000 ))"
  fi
}

now_start="$(start_ms)"

# -------- 진단 로직 --------
state="000" 
content=""  

# 1. 점검 대상 파일 리스트 정의
# 가이드에 따라 inetd, xinetd, systemd 관련 설정 파일을 모두 점검 대상에 포함
CHECK_TARGETS=(
  "/etc/inetd.conf"
  "/etc/xinetd.conf"
  "/etc/systemd/system.conf"
)

# /etc/xinetd.d 디렉터리가 존재하면 내부 파일들도 점검 대상에 추가
if [ -d "/etc/xinetd.d" ]; then
  while IFS= read -r file; do
    CHECK_TARGETS+=("$file")
  done < <(find /etc/xinetd.d -type f 2>/dev/null)
fi

FOUND_VULN=0

# 2. 파일 점검 루프
for TARGET_FILE in "${CHECK_TARGETS[@]}"; do
  # 파일이 존재하지 않으면 건너뜀 (서비스 미설치 등)
  if [ ! -e "$TARGET_FILE" ]; then
    continue
  fi

  # 파일 정보 추출 (%U: 소유자, %a: 8진수 권한)
  # 2>/dev/null: 권한 문제 등으로 에러 발생 시 무시
  read -r F_OWNER F_PERM < <(stat -c "%U %a" "$TARGET_FILE" 2>/dev/null)

  # stat 실패 시 건너뜀
  [[ -z "$F_OWNER" ]] && continue

  IS_VULN=0
  VULN_REASON=""

  # [점검 1] 소유자 확인 (root 여야 함)
  if [ "$F_OWNER" != "root" ]; then
    IS_VULN=1
    VULN_REASON="Owner_is_not_root($F_OWNER)"
  fi

  # [점검 2] 권한 확인 (600 이하 여야 함)
  # 600 이하란? User(r/w), Group(None), Other(None)
  # 즉, Group과 Other 자리가 모두 0이어야 함. (예: 600, 400, 000은 양호 / 640, 644는 취약)
  
  # 권한 문자열 처리 (예: 0644 -> 644)
  PERM_STR="${F_PERM: -3}"
  PERM_G="${PERM_STR:1:1}" # Group
  PERM_O="${PERM_STR:2:1}" # Other

  # Group이나 Other가 0이 아니면 취약 (Write 뿐만 아니라 Read, Execute도 없어야 함)
  if [ "$PERM_G" -ne 0 ] || [ "$PERM_O" -ne 0 ]; then
    IS_VULN=1
    if [[ -n "$VULN_REASON" ]]; then VULN_REASON="${VULN_REASON}, "; fi
    VULN_REASON="${VULN_REASON}Perm_is_greater_than_600($F_PERM)"
  fi

  # 취약점 발견 시 기록
  if [ "$IS_VULN" -eq 1 ]; then
    FOUND_VULN=1
    # 탭(\t) 구분자로 상세 내용 누적
    # 기존 content가 있으면 뒤에 탭 추가 후 이어쓰기
    if [[ -n "$content" ]]; then content="${content}\t"; fi
    content="${content}${TARGET_FILE}(${VULN_REASON})"
  fi
done

# 3. 최종 결과 상태 판단
if [ "$FOUND_VULN" -eq 1 ]; then
  state="201" # 취약
else
  state="000" # 양호
  if [[ -z "$content" ]]; then
    # 점검 대상 파일들이 아예 없는 경우(예: 최소 설치)도 양호로 간주하되 로그 남김
    # 필요 시 "No_Targets_Found" 등으로 수정 가능
    :
  fi
fi

now_end="$(start_ms)"
duration_ms=$(( now_end - now_start ))
if (( duration_ms < 0 )); then duration_ms=0; fi

# -------- 로그 작성 --------
{
  echo "check_id ${CHECK_ID}"
  echo "state_code ${CHECK_ID}-${state}"
  echo "check_duration_ms ${duration_ms}"
  if [[ -n "${content}" ]]; then
    echo -e "content ${content}"
  fi
} > "${LOG_FILE}"