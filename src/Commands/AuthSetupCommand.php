<?php

namespace Cube\Packages\Auth\Commands;

use Cube\App\App;
use Cube\App\Directory;
use Cube\Commands\BaseCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AuthSetupCommand extends BaseCommand
{
    protected static $defaultName = 'auth:setup';

    public function configure()
    {
        $this
            ->setDescription('Sets up authentication package')
            ->setHelp('This command helps complete the necessary setup required for authentication');
    }

    public function execute(InputInterface $input, OutputInterface $output)
    {
        $app = App::getRunningInstance();
        $copy_dir = __DIR__ . '/../stubs';
        $dir = $app->getPath(Directory::PATH_ROOT);

        $move_config = function ($name) use ($copy_dir, $dir) {

            $copy_filename = $copy_dir . '/' . $name . '.stub';
            $filename = $dir . '/' . $name;

            if (file_exists($filename)) {
                return;
            }

            copy($copy_filename, $filename);
        };

        $move_config('config/auth.php');
        $move_config('app/Middlewares/Authentication.php');

        $output->writeln('<fg=green>Auth setup completed!</>');
        return Command::SUCCESS;
    }
}
