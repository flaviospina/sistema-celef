<?php
// cron/flush_sheet_log.php — envia a fila de registros para a planilha de logs e segurança.
// cPanel → Cron Jobs (a cada 5 min):  */5 * * * *  /usr/local/bin/php /home/<usuario>/<dominio>/cron/flush_sheet_log.php
declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

use App\Cron\JobRunner;
use App\Google\SheetLogger;
use App\Security\SecurityEvents;

exit(JobRunner::run('flush_sheet_log', static function (int $deadline): string {
    // eventos criados por trigger (alteração fora da aplicação) ganham auditoria e alerta aqui também
    $alerted = SecurityEvents::alertPendingTriggerEvents();
    $r = SheetLogger::flush($deadline);
    return $r['mensagem'] . ($alerted > 0 ? " {$alerted} evento(s) de trigger alertado(s)." : '');
}));
